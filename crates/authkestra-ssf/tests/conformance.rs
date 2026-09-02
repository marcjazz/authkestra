//! End-to-end conformance suite for SET ingestion (RFC 8417), CAEP 1.0 event decoding, and
//! RFC 8935 push delivery.
//!
//! Every test here drives the public API only — mint a token with the fixture transmitter in
//! [`support`], hand it to a verifier or a receiver, and assert on the outcome a specification
//! paragraph requires. Where a test encodes a specific normative sentence, the citation is in
//! the test's own comment.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::json;

use authkestra_ssf::{
    AssuranceLevel, AssuranceLevelChange, CaepEvent, CaepMetadata, ChangeDirection, ChangeType,
    ComplianceStatus, CredentialChange, CredentialType, DeviceComplianceChange, HandlerError,
    InMemorySetReplayGuard, InitiatingEntity, LoggingHandler, PushReceiver, PushResponse,
    SecurityEventToken, SessionRevoked, SetError, SetErrorCode, SetHandler, SetVerifier,
    StaticKeyResolver, SubjectIdentifier, TokenClaimsChange, DEFAULT_MAX_BODY_BYTES,
    EVENT_TYPE_ASSURANCE_LEVEL_CHANGE, EVENT_TYPE_CREDENTIAL_CHANGE,
    EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE, EVENT_TYPE_SESSION_REVOKED,
    EVENT_TYPE_TOKEN_CLAIMS_CHANGE, SET_MEDIA_TYPE,
};

use support::{
    decoding_key, session_revoked_claims, sign, sign_with, tamper_signature, unsecured, with_claim,
    with_events, AUDIENCE, ISSUER, NOW,
};

/// A verifier with the audience check on and no replay guard.
fn verifier() -> SetVerifier {
    SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .build()
        .expect("fixture verifier configuration is complete")
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn accepts_a_well_formed_set() {
    let token = sign(&session_revoked_claims());
    let set = verifier()
        .verify_at(&token, NOW)
        .await
        .expect("a conformant SET must be accepted");

    assert_eq!(set.iss, ISSUER);
    assert_eq!(set.jti, "24c63fb56e5a2d77a6b512616ca9fa24");
    assert_eq!(set.iat, NOW);
    assert!(set.aud.as_ref().unwrap().contains(AUDIENCE));
    assert!(set.contains_event(EVENT_TYPE_SESSION_REVOKED));
    // RFC 8417 §2.2: `exp` is NOT RECOMMENDED, so its absence is not an error.
    assert!(set.exp.is_none());
}

#[tokio::test]
async fn accepts_the_full_media_type_spelling_of_typ() {
    // RFC 8417 §2.3 says the `application/` prefix SHOULD be omitted — "should", not "must".
    let token = sign_with(
        Some("application/secevent+jwt"),
        Algorithm::HS256,
        None,
        &session_revoked_claims(),
    );
    assert!(verifier().verify_at(&token, NOW).await.is_ok());
}

#[tokio::test]
async fn accepts_a_set_without_aud_when_no_audience_is_configured() {
    let claims = with_claim(session_revoked_claims(), "aud", json!(null));
    let token = sign(&claims);

    let verifier = SetVerifier::builder(ISSUER)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .build()
        .unwrap();
    assert!(verifier.verify_at(&token, NOW).await.is_ok());
}

#[tokio::test]
async fn accepts_an_audience_array_containing_the_expected_value() {
    let claims = with_claim(
        session_revoked_claims(),
        "aud",
        json!(["https://other.example.com/", AUDIENCE]),
    );
    let token = sign(&claims);
    assert!(verifier().verify_at(&token, NOW).await.is_ok());
}

#[tokio::test]
async fn verify_uses_the_system_clock() {
    // `verify` differs from `verify_at` only in where "now" comes from; mint a SET at the real
    // current time to prove that path is wired up.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = with_claim(session_revoked_claims(), "iat", json!(now));
    let token = sign(&claims);
    assert!(verifier().verify(&token).await.is_ok());
}

// ---------------------------------------------------------------------------
// Explicit typing (RFC 8417 §2.3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_missing_typ_header() {
    let token = sign_with(None, Algorithm::HS256, None, &session_revoked_claims());
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    assert!(matches!(err, SetError::MissingType), "{err:?}");
    assert_eq!(err.code(), SetErrorCode::InvalidRequest);
}

#[tokio::test]
async fn rejects_a_wrong_typ_header() {
    // An ID Token presented as a SET is exactly the confusion RFC 8417 §4.1 warns about.
    let token = sign_with(
        Some("JWT"),
        Algorithm::HS256,
        None,
        &session_revoked_claims(),
    );
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    assert_eq!(err, SetError::UnexpectedType("JWT".to_string()));
}

// ---------------------------------------------------------------------------
// Signature and algorithm
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_a_tampered_signature() {
    let token = tamper_signature(&sign(&session_revoked_claims()));
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    assert!(matches!(err, SetError::InvalidSignature(_)), "{err:?}");
    assert_eq!(err.code(), SetErrorCode::AuthenticationFailed);
}

#[tokio::test]
async fn rejects_an_unsecured_jwt() {
    // RFC 8417 §2.4's own worked example is an unsecured JWT. Accepting one would make every
    // other check in this suite decorative.
    let token = unsecured(&session_revoked_claims());
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    match &err {
        SetError::DisallowedAlgorithm(message) => assert!(message.contains("none"), "{message}"),
        other => panic!("expected DisallowedAlgorithm, got {other:?}"),
    }
    assert_eq!(err.code(), SetErrorCode::InvalidKey);
}

#[tokio::test]
async fn rejects_an_algorithm_outside_the_allow_list() {
    let token = sign_with(
        Some("secevent+jwt"),
        Algorithm::HS384,
        None,
        &session_revoked_claims(),
    );
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    match &err {
        SetError::DisallowedAlgorithm(message) => {
            assert!(message.contains("allow-list"), "{message}")
        }
        other => panic!("expected DisallowedAlgorithm, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_a_garbage_body() {
    let err = verifier().verify_at("not-a-jwt", NOW).await.unwrap_err();
    assert!(matches!(err, SetError::Malformed(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// Key resolution by kid
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolves_the_key_by_kid() {
    let resolver = Arc::new(StaticKeyResolver::new().with_key("k1", decoding_key()));
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key_resolver(resolver)
        .build()
        .unwrap();

    let token = sign_with(
        Some("secevent+jwt"),
        Algorithm::HS256,
        Some("k1"),
        &session_revoked_claims(),
    );
    assert!(verifier.verify_at(&token, NOW).await.is_ok());

    let token = sign_with(
        Some("secevent+jwt"),
        Algorithm::HS256,
        Some("k2"),
        &session_revoked_claims(),
    );
    let err = verifier.verify_at(&token, NOW).await.unwrap_err();
    assert!(matches!(err, SetError::KeyResolution(_)), "{err:?}");
    assert_eq!(err.code(), SetErrorCode::InvalidKey);
}

// ---------------------------------------------------------------------------
// Issuer and audience (RFC 8935 §2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_an_unrecognised_issuer() {
    let claims = with_claim(
        session_revoked_claims(),
        "iss",
        json!("https://evil.example.com/"),
    );
    let token = sign(&claims);
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    assert_eq!(
        err,
        SetError::IssuerMismatch {
            expected: ISSUER.to_string(),
            found: "https://evil.example.com/".to_string(),
        }
    );
    assert_eq!(err.code(), SetErrorCode::InvalidIssuer);
}

#[tokio::test]
async fn rejects_a_set_addressed_to_someone_else() {
    let claims = with_claim(
        session_revoked_claims(),
        "aud",
        json!("https://other.example.com/caep"),
    );
    let token = sign(&claims);
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    assert!(matches!(err, SetError::AudienceMismatch { .. }), "{err:?}");
    assert_eq!(err.code(), SetErrorCode::InvalidAudience);
}

#[tokio::test]
async fn rejects_a_missing_aud_when_an_audience_is_configured() {
    let claims = with_claim(session_revoked_claims(), "aud", json!(null));
    let token = sign(&claims);
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    assert!(matches!(err, SetError::MissingAudience { .. }), "{err:?}");
    assert_eq!(err.code(), SetErrorCode::InvalidAudience);
}

// ---------------------------------------------------------------------------
// Freshness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_an_iat_beyond_the_leeway_but_accepts_one_inside_it() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .iat_leeway(Duration::from_secs(30))
        .build()
        .unwrap();

    let inside = sign(&with_claim(
        session_revoked_claims(),
        "iat",
        json!(NOW + 30),
    ));
    assert!(verifier.verify_at(&inside, NOW).await.is_ok());

    let beyond = sign(&with_claim(
        session_revoked_claims(),
        "iat",
        json!(NOW + 31),
    ));
    let err = verifier.verify_at(&beyond, NOW).await.unwrap_err();
    assert!(matches!(err, SetError::IatInFuture { .. }), "{err:?}");
}

#[tokio::test]
async fn rejects_a_set_older_than_the_configured_maximum_age() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .iat_leeway(Duration::from_secs(0))
        .max_age(Duration::from_secs(60))
        .build()
        .unwrap();

    let token = sign(&with_claim(
        session_revoked_claims(),
        "iat",
        json!(NOW - 61),
    ));
    let err = verifier.verify_at(&token, NOW).await.unwrap_err();
    assert!(matches!(err, SetError::TooOld { .. }), "{err:?}");
}

#[tokio::test]
async fn honours_exp_when_a_transmitter_sends_one() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .iat_leeway(Duration::from_secs(0))
        .build()
        .unwrap();

    let token = sign(&with_claim(session_revoked_claims(), "exp", json!(NOW - 1)));
    let err = verifier.verify_at(&token, NOW).await.unwrap_err();
    assert!(matches!(err, SetError::Expired { .. }), "{err:?}");

    let token = sign(&with_claim(session_revoked_claims(), "exp", json!(NOW + 1)));
    assert!(verifier.verify_at(&token, NOW).await.is_ok());
}

#[tokio::test]
async fn accepts_and_ignores_an_nbf_claim() {
    // RFC 8417 never profiles `nbf`. A SET carrying one — even a wildly future one — is not
    // thereby invalid, and the claim is still surfaced to the caller.
    let token = sign(&with_claim(
        session_revoked_claims(),
        "nbf",
        json!(NOW + 86_400),
    ));
    let set = verifier().verify_at(&token, NOW).await.unwrap();
    assert_eq!(set.nbf, Some(NOW + 86_400));
}

// ---------------------------------------------------------------------------
// Claims profile
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_an_empty_events_claim() {
    let token = sign(&with_events(session_revoked_claims(), json!({})));
    let err = verifier().verify_at(&token, NOW).await.unwrap_err();
    assert_eq!(err, SetError::EmptyEvents);
    assert_eq!(err.code(), SetErrorCode::InvalidRequest);
}

#[tokio::test]
async fn rejects_a_set_missing_a_required_claim() {
    for missing in ["iss", "jti", "iat", "events"] {
        let token = sign(&with_claim(session_revoked_claims(), missing, json!(null)));
        let err = verifier().verify_at(&token, NOW).await.unwrap_err();
        match &err {
            SetError::InvalidClaims(message) => assert!(message.contains(missing), "{message}"),
            // A missing `iss` is caught by the claim parser, not the issuer check, because the
            // claim is not optional in the model.
            other => panic!("expected InvalidClaims for {missing}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn parses_the_sub_id_claim() {
    let claims = with_claim(
        session_revoked_claims(),
        "sub_id",
        json!({ "format": "iss_sub", "iss": ISSUER, "sub": "145234573" }),
    );
    let set = verifier().verify_at(&sign(&claims), NOW).await.unwrap();
    assert_eq!(
        set.sub_id,
        Some(SubjectIdentifier::IssSub {
            iss: ISSUER.to_string(),
            sub: "145234573".to_string(),
        })
    );
}

#[tokio::test]
async fn rejects_a_malformed_sub_id_claim() {
    let claims = with_claim(
        session_revoked_claims(),
        "sub_id",
        json!({ "email": "a@b" }),
    );
    let err = verifier().verify_at(&sign(&claims), NOW).await.unwrap_err();
    assert!(matches!(err, SetError::InvalidClaims(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// Replay (RFC 8417 §2.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn detects_a_replayed_jti() {
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .replay_guard(Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(
            3600,
        ))))
        .build()
        .unwrap();

    let token = sign(&session_revoked_claims());
    assert!(verifier.verify_at(&token, NOW).await.is_ok());

    let err = verifier.verify_at(&token, NOW).await.unwrap_err();
    assert_eq!(
        err,
        SetError::Replay {
            jti: "24c63fb56e5a2d77a6b512616ca9fa24".to_string(),
            iss: ISSUER.to_string(),
        }
    );
}

#[tokio::test]
async fn a_rejected_set_does_not_consume_its_jti() {
    // The replay guard runs last precisely so that a SET rejected for some other reason can be
    // corrected and retransmitted under the same jti.
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .replay_guard(Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(
            3600,
        ))))
        .build()
        .unwrap();

    let bad = sign_with(
        Some("JWT"),
        Algorithm::HS256,
        None,
        &session_revoked_claims(),
    );
    assert!(verifier.verify_at(&bad, NOW).await.is_err());

    let good = sign(&session_revoked_claims());
    assert!(
        verifier.verify_at(&good, NOW).await.is_ok(),
        "the same jti must still be accepted after an unrelated rejection"
    );
}

// ---------------------------------------------------------------------------
// CAEP event decoding, end to end
// ---------------------------------------------------------------------------

async fn decode_single_event(events: serde_json::Value) -> CaepEvent {
    let token = sign(&with_events(session_revoked_claims(), events));
    let set = verifier()
        .verify_at(&token, NOW)
        .await
        .expect("fixture SET must verify");
    let mut decoded = set.caep_events().expect("event payloads must decode");
    assert_eq!(decoded.len(), 1);
    decoded.remove(0)
}

#[tokio::test]
async fn decodes_every_modelled_caep_event_type() {
    let event = decode_single_event(json!({
        EVENT_TYPE_SESSION_REVOKED: {
            "subject": { "format": "email", "email": "user@example.com" },
            "initiating_entity": "admin",
            "reason_admin": { "en": "Compromised credentials" }
        }
    }))
    .await;
    let CaepEvent::SessionRevoked(revoked) = &event else {
        panic!("expected SessionRevoked, got {event:?}");
    };
    assert_eq!(
        revoked.metadata.initiating_entity,
        Some(InitiatingEntity::Admin)
    );
    assert_eq!(
        event.subject(),
        Some(&SubjectIdentifier::Email {
            email: "user@example.com".to_string()
        })
    );

    let event = decode_single_event(json!({
        EVENT_TYPE_TOKEN_CLAIMS_CHANGE: { "claims": { "role": "ro-admin" } }
    }))
    .await;
    let CaepEvent::TokenClaimsChange(change) = &event else {
        panic!("expected TokenClaimsChange, got {event:?}");
    };
    assert_eq!(change.claims["role"], "ro-admin");

    let event = decode_single_event(json!({
        EVENT_TYPE_CREDENTIAL_CHANGE: {
            "credential_type": "fido2-platform",
            "change_type": "revoke",
            "friendly_name": "Work laptop"
        }
    }))
    .await;
    let CaepEvent::CredentialChange(change) = &event else {
        panic!("expected CredentialChange, got {event:?}");
    };
    assert_eq!(change.credential_type, CredentialType::Fido2Platform);
    assert_eq!(change.change_type, ChangeType::Revoke);

    let event = decode_single_event(json!({
        EVENT_TYPE_ASSURANCE_LEVEL_CHANGE: {
            "current_level": "nist-aal3",
            "previous_level": "nist-aal1",
            "change_direction": "increase"
        }
    }))
    .await;
    let CaepEvent::AssuranceLevelChange(change) = &event else {
        panic!("expected AssuranceLevelChange, got {event:?}");
    };
    assert_eq!(change.current_level, AssuranceLevel::Aal3);
    assert_eq!(change.previous_level, AssuranceLevel::Aal1);
    assert_eq!(change.change_direction, ChangeDirection::Increase);

    let event = decode_single_event(json!({
        EVENT_TYPE_DEVICE_COMPLIANCE_CHANGE: {
            "previous_status": "compliant",
            "current_status": "not-compliant"
        }
    }))
    .await;
    let CaepEvent::DeviceComplianceChange(change) = &event else {
        panic!("expected DeviceComplianceChange, got {event:?}");
    };
    assert_eq!(change.previous_status, ComplianceStatus::Compliant);
    assert_eq!(change.current_status, ComplianceStatus::NotCompliant);
}

#[tokio::test]
async fn preserves_an_unknown_event_alongside_a_known_one() {
    let risc = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
    let token = sign(&with_events(
        session_revoked_claims(),
        json!({
            EVENT_TYPE_SESSION_REVOKED: {},
            risc: { "reason": "hijacking" }
        }),
    ));
    let set = verifier().verify_at(&token, NOW).await.unwrap();
    let events = set.caep_events().unwrap();

    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .any(|event| matches!(event, CaepEvent::SessionRevoked(_))));
    let unknown = events
        .iter()
        .find(|event| event.event_type_uri() == risc)
        .expect("the unknown event must survive decoding");
    match unknown {
        CaepEvent::Unknown { payload, .. } => assert_eq!(payload["reason"], "hijacking"),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// RFC 8935 push delivery
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RecordingHandler {
    seen: Mutex<Vec<String>>,
}

#[async_trait]
impl SetHandler for RecordingHandler {
    async fn handle(
        &self,
        _set: &SecurityEventToken,
        event: &CaepEvent,
    ) -> Result<(), HandlerError> {
        self.seen
            .lock()
            .unwrap()
            .push(event.event_type_uri().to_string());
        Ok(())
    }
}

struct FailingHandler {
    error: HandlerError,
    calls: AtomicUsize,
}

#[async_trait]
impl SetHandler for FailingHandler {
    async fn handle(
        &self,
        _set: &SecurityEventToken,
        _event: &CaepEvent,
    ) -> Result<(), HandlerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.error.clone())
    }
}

fn receiver_with(handler: Arc<dyn SetHandler>) -> PushReceiver {
    PushReceiver::new(Arc::new(verifier())).with_handler(handler)
}

fn error_body(response: &PushResponse) -> serde_json::Value {
    serde_json::from_slice(response.body()).expect("a failure body is JSON")
}

#[tokio::test]
async fn accepts_a_pushed_set_and_dispatches_its_events() {
    let handler = Arc::new(RecordingHandler::default());
    let receiver = receiver_with(handler.clone());

    // A fresh `iat` because `PushReceiver` verifies against the real clock.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = sign(&with_claim(session_revoked_claims(), "iat", json!(now)));

    let response = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;

    // RFC 8935 §2.2: 202 with an empty body.
    assert_eq!(response.status(), 202);
    assert!(response.body().is_empty());
    assert!(response.is_accepted());
    assert_eq!(
        handler.seen.lock().unwrap().as_slice(),
        [EVENT_TYPE_SESSION_REVOKED]
    );
}

#[tokio::test]
async fn rejects_a_wrong_content_type() {
    let receiver = receiver_with(Arc::new(LoggingHandler));
    let response = receiver
        .receive(Some("application/json"), b"whatever")
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code(), Some(SetErrorCode::InvalidRequest));
    assert_eq!(response.content_type(), Some("application/json"));
    assert_eq!(response.content_language(), Some("en"));
    assert_eq!(error_body(&response)["err"], "invalid_request");
}

#[tokio::test]
async fn rejects_a_missing_content_type() {
    let receiver = receiver_with(Arc::new(LoggingHandler));
    let response = receiver.receive(None, b"whatever").await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code(), Some(SetErrorCode::InvalidRequest));
}

#[tokio::test]
async fn rejects_a_non_utf8_body() {
    let receiver = receiver_with(Arc::new(LoggingHandler));
    let response = receiver.receive(Some(SET_MEDIA_TYPE), &[0xff, 0xfe]).await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code(), Some(SetErrorCode::InvalidRequest));
    assert!(error_body(&response)["description"]
        .as_str()
        .unwrap()
        .contains("UTF-8"));
}

#[tokio::test]
async fn maps_each_validation_failure_to_its_registered_error_code() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let fresh = |claims: serde_json::Value| with_claim(claims, "iat", json!(now));

    // invalid_request: a JWT that is not explicitly typed as a SET.
    let cases: Vec<(String, SetErrorCode)> = vec![
        (
            sign_with(
                Some("JWT"),
                Algorithm::HS256,
                None,
                &fresh(session_revoked_claims()),
            ),
            SetErrorCode::InvalidRequest,
        ),
        // invalid_key: an unsecured JWT.
        (
            unsecured(&fresh(session_revoked_claims())),
            SetErrorCode::InvalidKey,
        ),
        // authentication_failed: a tampered signature.
        (
            tamper_signature(&sign(&fresh(session_revoked_claims()))),
            SetErrorCode::AuthenticationFailed,
        ),
        // invalid_issuer.
        (
            sign(&fresh(with_claim(
                session_revoked_claims(),
                "iss",
                json!("https://evil.example.com/"),
            ))),
            SetErrorCode::InvalidIssuer,
        ),
        // invalid_audience.
        (
            sign(&fresh(with_claim(
                session_revoked_claims(),
                "aud",
                json!("https://other.example.com/"),
            ))),
            SetErrorCode::InvalidAudience,
        ),
        // invalid_request: an event payload that does not conform to its definition.
        (
            sign(&fresh(with_events(
                session_revoked_claims(),
                json!({ EVENT_TYPE_CREDENTIAL_CHANGE: {} }),
            ))),
            SetErrorCode::InvalidRequest,
        ),
    ];

    let receiver = receiver_with(Arc::new(LoggingHandler));
    for (token, expected) in cases {
        let response = receiver
            .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
            .await;
        assert_eq!(response.status(), 400);
        assert_eq!(response.error_code(), Some(expected));
        assert_eq!(error_body(&response)["err"], expected.as_str());
        assert!(!error_body(&response)["description"]
            .as_str()
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn a_rejecting_handler_yields_access_denied() {
    let handler = Arc::new(FailingHandler {
        error: HandlerError::Rejected("unknown tenant".to_string()),
        calls: AtomicUsize::new(0),
    });
    let receiver = receiver_with(handler.clone());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = sign(&with_claim(session_revoked_claims(), "iat", json!(now)));

    let response = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code(), Some(SetErrorCode::AccessDenied));
    assert_eq!(error_body(&response)["err"], "access_denied");
    assert_eq!(error_body(&response)["description"], "unknown tenant");
    assert_eq!(handler.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_failing_handler_yields_a_server_error_not_a_set_error_code() {
    let handler = Arc::new(FailingHandler {
        error: HandlerError::Internal("session store unreachable".to_string()),
        calls: AtomicUsize::new(0),
    });
    let receiver = receiver_with(handler.clone());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = sign(&with_claim(session_revoked_claims(), "iat", json!(now)));

    let response = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    assert_eq!(response.status(), 500);
    assert!(response.body().is_empty());
    assert_eq!(response.error_code(), None);
}

#[tokio::test]
async fn a_retransmitted_set_is_acknowledged_without_re_dispatching() {
    // RFC 8935 §2: "The SET Transmitter MAY transmit the same SET to the SET Recipient multiple
    // times... The SET Recipient MUST respond as it would if the SET had not been previously
    // received by the SET Recipient." So: 202 both times, handlers run once.
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .replay_guard(Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(
            3600,
        ))))
        .build()
        .unwrap();
    let handler = Arc::new(RecordingHandler::default());
    let receiver = PushReceiver::new(Arc::new(verifier)).with_handler(handler.clone());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = sign(&with_claim(session_revoked_claims(), "iat", json!(now)));

    let first = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    let second = receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;

    assert_eq!(first.status(), 202);
    assert_eq!(second.status(), 202, "a retransmission must not 400");
    assert_eq!(
        handler.seen.lock().unwrap().len(),
        1,
        "handlers must not run twice for the same SET"
    );
}

#[tokio::test]
async fn a_receiver_without_handlers_still_validates() {
    let receiver = PushReceiver::new(Arc::new(verifier()));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let token = sign(&with_claim(session_revoked_claims(), "iat", json!(now)));
    assert!(receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await
        .is_accepted());

    let token = tamper_signature(&token);
    assert!(!receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await
        .is_accepted());
}

#[tokio::test]
async fn tolerates_surrounding_whitespace_in_the_body() {
    let receiver = PushReceiver::new(Arc::new(verifier()));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = sign(&with_claim(session_revoked_claims(), "iat", json!(now)));
    let body = format!("\n{token}\n");

    assert!(receiver
        .receive(Some(SET_MEDIA_TYPE), body.as_bytes())
        .await
        .is_accepted());
}

#[tokio::test]
async fn the_verifier_is_debug_printable_without_leaking_keys() {
    let debug = format!("{:?}", verifier());
    assert!(debug.contains("issuer"));
    assert!(!debug.contains("DecodingKey"), "{debug}");
}

#[test]
fn decoding_key_helper_is_usable_standalone() {
    // Guards against the fixture drifting from `DecodingKey::from_secret`.
    let _: DecodingKey = decoding_key();
}

// ---------------------------------------------------------------------------
// Consumer ergonomics: every `#[non_exhaustive]` model must still be buildable
// from *outside* this crate, or a downstream service cannot unit-test the code
// that maps these types onto its own domain (authkestra#282).
// ---------------------------------------------------------------------------

#[test]
fn a_consumer_can_construct_every_public_model() {
    let mut events = std::collections::BTreeMap::new();
    events.insert(EVENT_TYPE_SESSION_REVOKED.to_string(), json!({}));
    let mut set = SecurityEventToken::new(ISSUER, "jti-1", NOW, events);
    set.sub_id = Some(SubjectIdentifier::Email {
        email: "user@example.com".to_string(),
    });
    assert_eq!(set.iss, ISSUER);
    assert_eq!(set.jti, "jti-1");
    assert_eq!(set.iat, NOW);
    assert!(set.contains_event(EVENT_TYPE_SESSION_REVOKED));
    assert!(set.aud.is_none());

    let mut metadata = CaepMetadata::empty();
    metadata.event_timestamp = Some(NOW);
    metadata.initiating_entity = Some(InitiatingEntity::Policy);
    assert_eq!(metadata.event_timestamp, Some(NOW));

    let mut revoked = SessionRevoked::default();
    revoked.metadata = metadata.clone();
    assert_eq!(
        revoked.metadata.initiating_entity,
        Some(InitiatingEntity::Policy)
    );

    let mut claims = serde_json::Map::new();
    claims.insert("role".to_string(), json!("ro-admin"));
    let mut token_claims_change = TokenClaimsChange::new(claims);
    token_claims_change.metadata = metadata.clone();
    assert_eq!(token_claims_change.claims["role"], "ro-admin");

    let mut credential_change = CredentialChange::new(CredentialType::Password, ChangeType::Update);
    credential_change.friendly_name = Some("Work laptop".to_string());
    assert_eq!(credential_change.change_type, ChangeType::Update);
    assert!(credential_change.x509_issuer.is_none());

    let assurance_change = AssuranceLevelChange::new(
        AssuranceLevel::Aal1,
        AssuranceLevel::Aal2,
        ChangeDirection::Decrease,
    );
    assert_eq!(assurance_change.current_level, AssuranceLevel::Aal1);

    let compliance_change =
        DeviceComplianceChange::new(ComplianceStatus::Compliant, ComplianceStatus::NotCompliant);
    assert_eq!(
        compliance_change.current_status,
        ComplianceStatus::NotCompliant
    );

    // The constructed values still round-trip through serde, so a consumer can use them as
    // fixtures for its own wire-level tests.
    for value in [
        serde_json::to_value(&revoked).unwrap(),
        serde_json::to_value(&token_claims_change).unwrap(),
        serde_json::to_value(&credential_change).unwrap(),
        serde_json::to_value(&assurance_change).unwrap(),
        serde_json::to_value(&compliance_change).unwrap(),
        serde_json::to_value(&set).unwrap(),
    ] {
        assert!(value.is_object());
    }
}

// ---------------------------------------------------------------------------
// jti must actually identify something (RFC 8417 section 2.2)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_an_empty_or_whitespace_only_jti() {
    for jti in ["", " ", "\t\n  "] {
        let token = sign(&with_claim(session_revoked_claims(), "jti", json!(jti)));
        let err = verifier().verify_at(&token, NOW).await.unwrap_err();
        assert_eq!(err, SetError::EmptyJti, "jti {jti:?} must be refused");
        assert_eq!(err.code(), SetErrorCode::InvalidRequest);
    }
}

#[tokio::test]
async fn an_empty_jti_cannot_poison_the_replay_guard() {
    // The point of the check: without it, the first empty-jti SET would occupy the issuer's
    // only "" slot and every later one would look like a replay.
    let verifier = SetVerifier::builder(ISSUER)
        .audience(AUDIENCE)
        .algorithms([Algorithm::HS256])
        .key(decoding_key())
        .replay_guard(Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(
            3600,
        ))))
        .build()
        .unwrap();

    let empty = sign(&with_claim(session_revoked_claims(), "jti", json!("")));
    assert_eq!(
        verifier.verify_at(&empty, NOW).await.unwrap_err(),
        SetError::EmptyJti
    );

    let good = sign(&session_revoked_claims());
    assert!(verifier.verify_at(&good, NOW).await.is_ok());
}

// ---------------------------------------------------------------------------
// Body size cap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_body_cap_accepts_exactly_the_limit_and_refuses_one_byte_more() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = sign(&with_claim(session_revoked_claims(), "iat", json!(now)));
    let len = token.len();

    let at_limit = PushReceiver::new(Arc::new(verifier())).with_max_body_bytes(len);
    let response = at_limit
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    assert_eq!(
        response.status(),
        202,
        "a body of exactly max_body_bytes must be accepted"
    );

    let one_short = PushReceiver::new(Arc::new(verifier())).with_max_body_bytes(len - 1);
    let response = one_short
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code(), Some(SetErrorCode::InvalidRequest));
    assert_eq!(error_body(&response)["err"], "invalid_request");
    assert!(error_body(&response)["description"]
        .as_str()
        .unwrap()
        .contains("exceeds the maximum"));
}

#[tokio::test]
async fn the_default_body_cap_lets_a_real_set_through() {
    let receiver = PushReceiver::new(Arc::new(verifier()));
    assert_eq!(receiver.max_body_bytes(), DEFAULT_MAX_BODY_BYTES);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = sign(&with_claim(session_revoked_claims(), "iat", json!(now)));
    assert!(token.len() < DEFAULT_MAX_BODY_BYTES);
    assert!(receiver
        .receive(Some(SET_MEDIA_TYPE), token.as_bytes())
        .await
        .is_accepted());

    // A body over the default is refused without the verifier ever being consulted.
    let oversized = vec![b'a'; DEFAULT_MAX_BODY_BYTES + 1];
    let response = receiver.receive(Some(SET_MEDIA_TYPE), &oversized).await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code(), Some(SetErrorCode::InvalidRequest));
}
