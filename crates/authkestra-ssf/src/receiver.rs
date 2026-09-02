//! The RFC 8935 push delivery receiver.
//!
//! [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935) ("Push-Based Security Event Token (SET)
//! Delivery Using HTTP") defines exactly one interaction: the transmitter POSTs a SET with
//! `Content-Type: application/secevent+jwt`, and the receiver answers `202 Accepted` with an
//! empty body, or `400 Bad Request` with a JSON `{"err": ..., "description": ...}` body.
//!
//! [`PushReceiver`] implements that interaction *without* an HTTP framework, per the workspace
//! `AGENTS.md` "Framework Agnostic" rule: it takes the content type and the raw body and returns
//! a [`PushResponse`] that an axum or actix handler can translate in a few lines. Wiring those
//! adapters is deliberately left to a follow-up.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::caep::CaepEvent;
use crate::error::{SetError, SetErrorCode};
use crate::set::{SecurityEventToken, SET_MEDIA_TYPE};
use crate::verify::SetVerifier;

/// The `Content-Language` RFC 8935 §2.3 requires on a failure response.
///
/// RFC 8935 §2.3 says the receiver SHOULD honour `Accept-Language` and MUST otherwise answer in
/// something an English speaker understands (RFC 2277 §4.5). This crate's `description` strings
/// are English only, so the value is fixed; a deployment that localizes them should override it.
pub const ERROR_CONTENT_LANGUAGE: &str = "en";

/// The `Content-Type` RFC 8935 §2.3 requires on a failure response body.
pub const ERROR_CONTENT_TYPE: &str = "application/json";

/// Why a [`SetHandler`] could not process an event.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HandlerError {
    /// The handler failed for a reason the transmitter cannot fix — a database was down, a
    /// downstream call timed out. Surfaced as a 5xx, because RFC 8935 §2.4's error codes all
    /// describe something *wrong with the SET*, and telling a transmitter its perfectly good SET
    /// was invalid would make it stop retrying the one thing that could still succeed.
    #[error("handler failed: {0}")]
    Internal(String),

    /// The handler refuses this SET from this transmitter (an unrecognised subject, a tenant the
    /// transmitter may not signal for). Maps to `access_denied`.
    #[error("handler rejected the event: {0}")]
    Rejected(String),
}

/// Does something with a validated SET.
///
/// Handlers see events one at a time, together with the SET they arrived in, because RFC 8417
/// §2.2 allows several event types per SET while forbidding several *independent logical* events
/// — so the SET-level claims (`iss`, `jti`, `sub_id`, `toe`) apply to each of them.
#[async_trait]
pub trait SetHandler: Send + Sync + 'static {
    /// Handles one event from `set`.
    async fn handle(&self, set: &SecurityEventToken, event: &CaepEvent)
        -> Result<(), HandlerError>;
}

/// A [`SetHandler`] that only traces what it received.
///
/// Useful as a first deployment step — turn on delivery, watch the events arrive, and confirm
/// the transmitter's configuration before anything acts on them.
pub struct LoggingHandler;

#[async_trait]
impl SetHandler for LoggingHandler {
    async fn handle(
        &self,
        set: &SecurityEventToken,
        event: &CaepEvent,
    ) -> Result<(), HandlerError> {
        tracing::info!(
            target: "authkestra_ssf",
            iss = %set.iss,
            jti = %set.jti,
            event_type = %event.event_type_uri(),
            subject_format = event.subject().map(|s| s.format()).unwrap_or("none"),
            "received SET event"
        );
        Ok(())
    }
}

/// What the caller's HTTP layer should send back.
///
/// Modelled as data rather than as a framework response type so that the same receiver serves
/// axum, actix, a queue consumer, or a test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushResponse {
    status: u16,
    content_type: Option<&'static str>,
    content_language: Option<&'static str>,
    body: Vec<u8>,
    error_code: Option<SetErrorCode>,
}

impl PushResponse {
    /// The RFC 8935 §2.2 success response: `202 Accepted`, empty body.
    pub fn accepted() -> Self {
        Self {
            status: 202,
            content_type: None,
            content_language: None,
            body: Vec::new(),
            error_code: None,
        }
    }

    /// An RFC 8935 §2.3 failure response: `400 Bad Request` with a JSON body carrying `err` and
    /// `description`.
    pub fn error(code: SetErrorCode, description: impl Into<String>) -> Self {
        let description = description.into();
        let body = serde_json::json!({ "err": code.as_str(), "description": description });
        Self {
            status: 400,
            content_type: Some(ERROR_CONTENT_TYPE),
            content_language: Some(ERROR_CONTENT_LANGUAGE),
            // `serde_json::to_vec` on an object of two strings cannot fail; the fallback keeps
            // the receiver infallible rather than importing a panic into a request path.
            body: serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
            error_code: Some(code),
        }
    }

    /// A `500 Internal Server Error` with an empty body, for a handler failure that is not the
    /// transmitter's fault. See [`HandlerError::Internal`].
    pub fn internal_error() -> Self {
        Self {
            status: 500,
            content_type: None,
            content_language: None,
            body: Vec::new(),
            error_code: None,
        }
    }

    /// The HTTP status code to send.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The `Content-Type` header value, if the response has a body.
    pub fn content_type(&self) -> Option<&'static str> {
        self.content_type
    }

    /// The `Content-Language` header value, which RFC 8935 §2.3 requires on failure responses.
    pub fn content_language(&self) -> Option<&'static str> {
        self.content_language
    }

    /// The response body, empty for success.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The RFC 8935 §2.4 error code carried in the body, if this is a failure response.
    pub fn error_code(&self) -> Option<SetErrorCode> {
        self.error_code
    }

    /// Whether this is the RFC 8935 §2.2 success response.
    pub fn is_accepted(&self) -> bool {
        self.status == 202
    }
}

/// Receives pushed SETs, validates them, and dispatches their events to handlers.
pub struct PushReceiver {
    verifier: Arc<SetVerifier>,
    handlers: Vec<Arc<dyn SetHandler>>,
}

impl PushReceiver {
    /// Creates a receiver that validates with `verifier` and, until handlers are added, only
    /// validates.
    pub fn new(verifier: Arc<SetVerifier>) -> Self {
        Self {
            verifier,
            handlers: Vec::new(),
        }
    }

    /// Adds a handler. Handlers run in the order they were added, and every handler sees every
    /// event; a handler that only cares about one event type filters on
    /// [`CaepEvent::event_type_uri`].
    pub fn with_handler(mut self, handler: Arc<dyn SetHandler>) -> Self {
        self.handlers.push(handler);
        self
    }

    /// Handles one SET Transmission Request (RFC 8935 §2.1).
    ///
    /// `content_type` is the request's `Content-Type` header, if any, and `body` its raw bytes.
    ///
    /// Two deliberate decisions:
    ///
    /// - **A replayed SET answers `202`, not an error.** RFC 8935 §2 is explicit: "The SET
    ///   Transmitter MAY transmit the same SET to the SET Recipient multiple times... The SET
    ///   Recipient MUST respond as it would if the SET had not been previously received." So the
    ///   replay guard suppresses *handler dispatch*, not the acknowledgement. Answering 400
    ///   would make a conformant transmitter retry forever.
    /// - **Handlers run before the response, not after.** RFC 8935 §2 recommends persisting the
    ///   SET and then doing further processing asynchronously. This crate has no store of its
    ///   own, so the handler *is* the persistence step; a 202 sent before it ran would promise
    ///   durability that nothing delivered. A deployment that wants the RFC's asynchronous shape
    ///   writes a handler that enqueues and returns immediately.
    pub async fn receive(&self, content_type: Option<&str>, body: &[u8]) -> PushResponse {
        if let Err(response) = check_content_type(content_type) {
            return response;
        }

        let token = match std::str::from_utf8(body) {
            Ok(token) => token.trim(),
            Err(err) => {
                tracing::warn!(
                    target: "authkestra_ssf",
                    error = %err,
                    "rejecting SET delivery: body is not UTF-8"
                );
                return PushResponse::error(
                    SetErrorCode::InvalidRequest,
                    "request body is not valid UTF-8",
                );
            }
        };

        let set = match self.verifier.verify(token).await {
            Ok(set) => set,
            Err(SetError::Replay { jti, iss }) => {
                tracing::info!(
                    target: "authkestra_ssf",
                    jti = %jti,
                    iss = %iss,
                    "SET already ingested; acknowledging without re-dispatching (RFC 8935 §2)"
                );
                return PushResponse::accepted();
            }
            Err(err) => {
                let code = err.code();
                tracing::warn!(
                    target: "authkestra_ssf",
                    code = %code,
                    error = %err,
                    "rejecting SET delivery"
                );
                return PushResponse::error(code, err.to_string());
            }
        };

        let events = match set.caep_events() {
            Ok(events) => events,
            Err(err) => {
                tracing::warn!(
                    target: "authkestra_ssf",
                    jti = %set.jti,
                    error = %err,
                    "rejecting SET delivery: event payload does not conform"
                );
                return PushResponse::error(SetErrorCode::InvalidRequest, err.to_string());
            }
        };

        for event in &events {
            for handler in &self.handlers {
                match handler.handle(&set, event).await {
                    Ok(()) => {}
                    Err(HandlerError::Rejected(reason)) => {
                        tracing::warn!(
                            target: "authkestra_ssf",
                            jti = %set.jti,
                            event_type = %event.event_type_uri(),
                            reason = %reason,
                            "handler rejected the event"
                        );
                        return PushResponse::error(SetErrorCode::AccessDenied, reason);
                    }
                    Err(HandlerError::Internal(reason)) => {
                        tracing::error!(
                            target: "authkestra_ssf",
                            jti = %set.jti,
                            event_type = %event.event_type_uri(),
                            reason = %reason,
                            "handler failed; answering 500 so the transmitter retries"
                        );
                        return PushResponse::internal_error();
                    }
                }
            }
        }

        tracing::debug!(
            target: "authkestra_ssf",
            jti = %set.jti,
            events = events.len(),
            handlers = self.handlers.len(),
            "SET delivery accepted"
        );
        PushResponse::accepted()
    }
}

/// RFC 8935 §2.1: the request's `Content-Type` MUST be `application/secevent+jwt`.
///
/// Parameters (`; charset=utf-8`) are ignored and the comparison is case-insensitive, per
/// RFC 9110 §8.3 / RFC 2045 §5.1 — a transmitter that spells the type in a legal but unusual way
/// is conformant, and rejecting it would be this receiver's bug, not theirs.
fn check_content_type(content_type: Option<&str>) -> Result<(), PushResponse> {
    let Some(content_type) = content_type else {
        tracing::warn!(
            target: "authkestra_ssf",
            "rejecting SET delivery: no Content-Type (RFC 8935 §2.1 requires one)"
        );
        return Err(PushResponse::error(
            SetErrorCode::InvalidRequest,
            format!("missing Content-Type: RFC 8935 §2.1 requires {SET_MEDIA_TYPE}"),
        ));
    };

    let essence = content_type.split(';').next().unwrap_or("").trim();
    if essence.eq_ignore_ascii_case(SET_MEDIA_TYPE) {
        return Ok(());
    }

    tracing::warn!(
        target: "authkestra_ssf",
        content_type = %content_type,
        "rejecting SET delivery: wrong Content-Type"
    );
    Err(PushResponse::error(
        SetErrorCode::InvalidRequest,
        format!(
            "unsupported Content-Type {content_type:?}: RFC 8935 §2.1 requires {SET_MEDIA_TYPE}"
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_required_content_type_with_parameters() {
        assert!(check_content_type(Some(SET_MEDIA_TYPE)).is_ok());
        assert!(check_content_type(Some("application/secevent+jwt; charset=UTF-8")).is_ok());
        assert!(check_content_type(Some("  Application/SecEvent+JWT  ")).is_ok());
    }

    #[test]
    fn rejects_a_missing_or_wrong_content_type() {
        let response = check_content_type(None).unwrap_err();
        assert_eq!(response.status(), 400);
        assert_eq!(response.error_code(), Some(SetErrorCode::InvalidRequest));
        assert!(String::from_utf8_lossy(response.body()).contains("missing Content-Type"));

        let response = check_content_type(Some("application/json")).unwrap_err();
        assert_eq!(response.error_code(), Some(SetErrorCode::InvalidRequest));
        assert!(String::from_utf8_lossy(response.body()).contains("unsupported Content-Type"));

        let response = check_content_type(Some("")).unwrap_err();
        assert_eq!(response.status(), 400);
    }

    #[test]
    fn success_response_matches_rfc_8935_section_2_2() {
        let response = PushResponse::accepted();
        assert_eq!(response.status(), 202);
        assert!(response.is_accepted());
        assert!(response.body().is_empty());
        assert_eq!(response.content_type(), None);
        assert_eq!(response.content_language(), None);
        assert_eq!(response.error_code(), None);
    }

    #[test]
    fn failure_response_matches_rfc_8935_section_2_3() {
        let response =
            PushResponse::error(SetErrorCode::InvalidKey, "Key ID 12345 has been revoked.");
        assert_eq!(response.status(), 400);
        assert!(!response.is_accepted());
        assert_eq!(response.content_type(), Some("application/json"));
        assert_eq!(response.content_language(), Some("en"));
        assert_eq!(response.error_code(), Some(SetErrorCode::InvalidKey));

        let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body["err"], "invalid_key");
        assert_eq!(body["description"], "Key ID 12345 has been revoked.");
    }

    #[test]
    fn internal_error_response_has_no_set_error_code() {
        let response = PushResponse::internal_error();
        assert_eq!(response.status(), 500);
        assert!(response.body().is_empty());
        assert_eq!(response.error_code(), None);
        assert!(!response.is_accepted());
    }

    #[tokio::test]
    async fn logging_handler_accepts_everything() {
        let set = SecurityEventToken {
            iss: "https://idp/".into(),
            jti: "jti".into(),
            iat: 0,
            aud: None,
            sub: None,
            sub_id: None,
            txn: None,
            toe: None,
            exp: None,
            nbf: None,
            events: Default::default(),
            additional: Default::default(),
        };
        let event = CaepEvent::Unknown {
            uri: "https://example.com/e".into(),
            payload: serde_json::json!({}),
        };
        assert!(LoggingHandler.handle(&set, &event).await.is_ok());
    }

    #[test]
    fn handler_errors_describe_themselves() {
        assert!(HandlerError::Internal("db down".into())
            .to_string()
            .contains("db down"));
        assert!(HandlerError::Rejected("unknown tenant".into())
            .to_string()
            .contains("unknown tenant"));
    }
}
