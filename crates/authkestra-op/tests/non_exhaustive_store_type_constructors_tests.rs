//! Proves `AuthorizationCode`, `DeviceCodeSession`, `RefreshToken`,
//! `TokenRequest` and `EnrolmentChallenge` are constructible from *outside*
//! the crate despite being `#[non_exhaustive]`.
//!
//! Being an integration test (a separate compilation unit under `tests/`,
//! not `#[cfg(test)] mod tests` inside the crate), `#[non_exhaustive]` is
//! genuinely enforced here: a bare struct literal for any of these types
//! would fail to *compile* in this file, because `non_exhaustive` only
//! restricts construction from outside the defining crate. Regression test
//! for authkestra#268.

use std::collections::HashMap;

use authkestra_engine::auth::state::Identity;
use authkestra_op::attestation::{EnrolmentChallenge, PrincipalType};
use authkestra_op::code::AuthorizationCode;
use authkestra_op::device::{DeviceCodeSession, DeviceCodeStatus};
use authkestra_op::handlers::token::TokenRequest;
use authkestra_op::refresh::RefreshToken;
use chrono::{Duration, Utc};

fn test_identity() -> Identity {
    Identity {
        provider_id: "test".to_string(),
        external_id: "user123".to_string(),
        username: Some("user123".to_string()),
        email: None,
        attributes: HashMap::new(),
    }
}

#[test]
fn authorization_code_is_constructible_and_used_is_not_silently_defaulted() {
    let expires_at = Utc::now() + Duration::seconds(60);

    let mut code = AuthorizationCode::new(
        "code-1".to_string(),
        "client-1".to_string(),
        "https://example.com/callback".to_string(),
        "openid".to_string(),
        test_identity(),
        expires_at,
        true, // reconstructing an already-spent code must not come back as unused
    );
    assert!(code.used);
    assert_eq!(code.code_challenge, None);

    // Optional fields are `pub`, so a store implementation can still set
    // them directly after construction.
    code.code_challenge = Some("challenge".to_string());
    assert_eq!(code.code_challenge.as_deref(), Some("challenge"));
}

#[test]
fn device_code_session_is_constructible() {
    let expires_at = Utc::now() + Duration::seconds(60);

    let session = DeviceCodeSession::new(
        "device-1".to_string(),
        "USER-CODE".to_string(),
        "client-1".to_string(),
        "openid".to_string(),
        expires_at,
        DeviceCodeStatus::Pending,
    );
    assert_eq!(session.last_polled_at, None);
}

#[test]
fn refresh_token_is_constructible() {
    let expires_at = Utc::now() + Duration::seconds(60);

    let refresh = RefreshToken::new(
        "refresh-1".to_string(),
        "client-1".to_string(),
        test_identity(),
        "openid".to_string(),
        expires_at,
    );
    assert_eq!(refresh.token, "refresh-1");
}

#[test]
fn token_request_is_constructible() {
    let request = TokenRequest::new("authorization_code".to_string());
    assert_eq!(request.grant_type, "authorization_code");
    assert_eq!(request.code, None);
}

#[test]
fn enrolment_challenge_is_constructible() {
    let expires_at = Utc::now() + Duration::seconds(60);

    let challenge = EnrolmentChallenge::new(
        "challenge-1".to_string(),
        "subject-1".to_string(),
        "principal-1".to_string(),
        PrincipalType::Device,
        serde_json::json!({"kty": "OKP"}),
        serde_json::json!({}),
        expires_at,
    );
    assert_eq!(challenge.challenge, "challenge-1");
}
