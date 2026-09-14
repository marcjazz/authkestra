//! Proves `AuthorizeOutcome` and `ReauthenticationRequired` behave as
//! intended now that both are `#[non_exhaustive]` (issue #381).
//!
//! Being an integration test (a separate compilation unit under `tests/`,
//! not `#[cfg(test)] mod tests` inside the crate), `#[non_exhaustive]` is
//! genuinely enforced here — mirroring
//! `non_exhaustive_store_type_constructors_tests.rs`'s rationale for the
//! store types:
//!
//! - `ReauthenticationRequired` is constructed via
//!   [`ReauthenticationRequired::new`], not a struct literal — a bare
//!   literal for it would fail to compile in this file.
//! - Matching on `AuthorizeOutcome` below requires a wildcard arm; deleting
//!   it would fail to compile in this file (though not inside
//!   `authkestra-op` itself, where exhaustive matches are still allowed).
//!   That is the whole point of adding `#[non_exhaustive]` now: the next
//!   variant this enum needs costs external callers nothing beyond already
//!   having that wildcard arm.
//! - `AuthorizeRequest`'s new `max_age`/`prompt` fields round-trip through
//!   the same deserialization path a real HTTP framework's `Query`/`Form`
//!   extractor already uses (see `authkestra-axum`/`authkestra-actix`),
//!   which remains the only way to construct `AuthorizeRequest` from
//!   outside this crate now that it, too, is `#[non_exhaustive]`.

use authkestra_op::handlers::authorize::{AuthorizeOutcome, AuthorizeRequest};

fn deserialize_request(max_age: Option<i64>, prompt: Option<&str>) -> AuthorizeRequest {
    let mut value = serde_json::json!({
        "client_id": "client-1",
        "redirect_uri": "https://example.com/callback",
        "response_type": "code",
    });
    if let Some(max_age) = max_age {
        value["max_age"] = serde_json::json!(max_age);
    }
    if let Some(prompt) = prompt {
        value["prompt"] = serde_json::json!(prompt);
    }
    serde_json::from_value(value).expect("AuthorizeRequest should deserialize")
}

#[test]
fn authorize_request_deserializes_max_age_and_prompt_when_present() {
    let req = deserialize_request(Some(0), Some("login"));
    assert_eq!(req.max_age, Some(0));
    assert_eq!(req.prompt.as_deref(), Some("login"));
}

#[test]
fn authorize_request_defaults_max_age_and_prompt_when_absent() {
    let req = deserialize_request(None, None);
    assert_eq!(req.max_age, None);
    assert_eq!(req.prompt, None);
}

#[test]
fn reauthentication_required_is_constructible_from_outside_the_crate() {
    let req = deserialize_request(Some(3600), None);
    let reauth =
        authkestra_op::handlers::authorize::ReauthenticationRequired::new(req, true, false);
    assert!(reauth.max_age_exceeded);
    assert!(!reauth.prompt_login);
    assert_eq!(reauth.request.client_id, "client-1");
}

/// A wildcard arm is mandatory here for `AuthorizeOutcome` (a
/// `#[non_exhaustive]` enum matched from outside its defining crate) to
/// compile at all. This function's existence — and the fact that it
/// compiles — is the regression test: deleting the `_ => ...` arm below (or
/// the `#[non_exhaustive]` attribute on `AuthorizeOutcome` itself) would
/// break this file's build.
fn describe_outcome(outcome: &AuthorizeOutcome) -> &'static str {
    match outcome {
        AuthorizeOutcome::Redirect(_) => "redirect",
        AuthorizeOutcome::DirectError(_) => "direct_error",
        _ => "other",
    }
}

#[test]
fn authorize_outcome_requires_a_wildcard_arm_outside_the_crate() {
    let req = deserialize_request(Some(60), None);
    let reauth =
        authkestra_op::handlers::authorize::ReauthenticationRequired::new(req, true, false);
    let outcome = AuthorizeOutcome::ReauthenticationRequired(Box::new(reauth));
    assert_eq!(describe_outcome(&outcome), "other");
    assert_eq!(
        describe_outcome(&AuthorizeOutcome::Redirect(
            "https://example.com".to_string()
        )),
        "redirect"
    );
}
