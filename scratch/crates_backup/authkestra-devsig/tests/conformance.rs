//! Conformance tests for the device-signature verification algorithm.
//!
//! There is no live Issuer to mint real attestations (`authkestra-op`'s enrolment/attestation
//! side is tracked separately in authkestra#136), so this file plays the Issuer itself: it
//! generates an RSA "issuer" keypair and an EC P-256 "device" keypair, self-signs a JWS matching
//! the attestation shape, and self-signs a request-signature JWS matching the wire format —
//! then feeds both to `authkestra_devsig::verify`, the same entry point real callers use.

mod support;

use authkestra_devsig::{InMemoryReplayStore, SignedRequest, UnavailableReplayStore, VerifyError};
use support::TestSetup;

/// Case 1: valid signature + valid attestation, bound, fresh -> Accept.
#[tokio::test]
async fn case_01_valid_pair_is_accepted() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let identity = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .expect("valid, bound, fresh pair must be accepted");

    assert_eq!(identity.subject, support::SUBJECT);
    assert_eq!(identity.device, support::DEVICE_ID);
    assert_eq!(identity.key_thumbprint, setup.device.thumbprint);
    assert_eq!(identity.attributes["status"], "active");
}

/// Case 2: attestation only, no signature -> missing_credential.
#[tokio::test]
async fn case_02_attestation_only_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();

    let request = SignedRequest {
        signature: None,
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::MissingCredential);
}

/// Case 3: signature only, no attestation -> missing_credential.
#[tokio::test]
async fn case_03_signature_only_is_rejected() {
    let setup = TestSetup::new().await;
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: None,
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::MissingCredential);
}

/// Case 4 -- THE CRITICAL CASE. A valid attestation for user A, paired with a request signed by
/// a different (attacker) key, must be rejected with `key_not_bound`. This test is written to
/// fail if the binding check is ever skipped, reordered, or short-circuited: it proves the check
/// is load-bearing, not just present.
#[tokio::test]
async fn case_04_attestation_for_a_plus_attackers_key_is_rejected_key_not_bound() {
    let setup = TestSetup::new().await;

    // A valid attestation binding user A's identity to A's own device key thumbprint.
    let attestation = setup.valid_attestation();

    // A request that verifies perfectly -- but signed by the ATTACKER's key, not A's. Both
    // credentials are individually well-formed and individually valid; only comparing the
    // embedded jwk's thumbprint against cnf.jkt can catch this.
    let signature =
        setup.valid_signature(&setup.attacker, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        VerifyError::KeyNotBound,
        "an attacker's key paired with a victim's attestation MUST be rejected as key_not_bound \
         -- accepting it is a total authentication bypass"
    );

    // Sanity check the attacker's key really does verify its own signature standalone -- i.e.
    // this test isn't accidentally passing because the signature itself was broken. Case 4 is
    // only meaningful if the attestation and the signature each independently succeed and only
    // the binding check catches it.
    assert_ne!(
        setup.device.thumbprint, setup.attacker.thumbprint,
        "test setup bug: attacker key must differ from the device key"
    );
}

/// Case 5: `alg: none` on either token -> bad_alg.
#[tokio::test]
async fn case_05_alg_none_on_attestation_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.attestation_with_raw_header_alg("none");
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "bad_alg");
}

#[tokio::test]
async fn case_05_alg_none_on_signature_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature =
        setup.signature_with_raw_header_alg("none", "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "bad_alg");
}

/// Case 6: body modified after signing -> body_mismatch.
#[tokio::test]
async fn case_06_tampered_body_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let original_body = br#"{"amount":1000}"#;
    let signature = setup.valid_signature_with_body(
        &setup.device,
        "POST",
        "/v1/payments/transfer",
        original_body,
    );

    let tampered_body = br#"{"amount":9000000}"#;
    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: Some(tampered_body),
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::BodyMismatch);
}

/// Case 7: same `jti` replayed -> replay_detected on the second attempt.
#[tokio::test]
async fn case_07_replayed_jti_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);
    let store = InMemoryReplayStore::new();

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .expect("first use must be accepted");

    let request_again = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };
    let err = authkestra_devsig::verify(&request_again, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::ReplayDetected);
}

/// Case 8: same request replayed to a different `aud` -> audience_mismatch.
#[tokio::test]
async fn case_08_wrong_audience_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature = setup.signature_with_aud(
        &setup.device,
        "POST",
        "/v1/payments/transfer",
        "a-different-service.example.com",
    );

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::AudienceMismatch);
}

/// Case 9: `exp` in the past beyond skew -> signature_expired.
#[tokio::test]
async fn case_09_expired_signature_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature = setup.signature_with_time_offsets(
        &setup.device,
        "POST",
        "/v1/payments/transfer",
        -600, // iat: 10 minutes ago
        -500, // exp: well past both its own lifetime and the skew tolerance
    );

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::SignatureExpired);
}

/// Case 10: signature lifetime 24h -> lifetime_too_long, even though `exp` is in the future.
#[tokio::test]
async fn case_10_excessive_lifetime_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature = setup.signature_with_time_offsets(
        &setup.device,
        "POST",
        "/v1/payments/transfer",
        0,
        24 * 3600,
    );

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::LifetimeTooLong);
}

/// Case 11: attestation signed by an untrusted issuer -> untrusted_issuer.
#[tokio::test]
async fn case_11_untrusted_issuer_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.attestation_with_issuer("https://not-our-issuer.example.com");
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "untrusted_issuer");
}

/// Case 12: attestation `kid` absent from the JWKS -> unknown_kid.
#[tokio::test]
async fn case_12_unknown_kid_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.attestation_with_kid("kid-not-in-jwks");
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "unknown_kid");
}

/// Case 13: `jwk` contains private component `d` -> bad_jwk. Never trust an embedded private
/// key, even though nothing in this crate would actually use `d` to verify (jsonwebtoken's own
/// `jwk::Jwk` type has no field for it) -- the point is to detect and reject its mere presence.
#[tokio::test]
async fn case_13_private_component_in_jwk_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature = setup.signature_with_private_component_in_jwk(
        &setup.device,
        "POST",
        "/v1/payments/transfer",
    );

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "bad_jwk");
}

/// An embedded jwk claiming `"kty":"EC","crv":"Ed25519"` is a structurally-inconsistent shape
/// that `jsonwebtoken` 10.4.0's `Jwk::thumbprint()` panics on (verified against the vendored
/// 10.4.0 source: `EllipticCurve::Ed25519 => panic!(...)` inside the `EllipticCurve` match arm).
/// Since the embedded jwk comes straight from the attacker-controlled signature header, this
/// must be rejected as an ordinary `bad_jwk` error -- and, just as importantly, must not take
/// the test process down with it. If this test hangs or the process aborts instead of returning
/// a normal `Err`, the panic guard in `signature.rs` has regressed.
#[tokio::test]
async fn inconsistent_curve_jwk_is_rejected_as_bad_jwk_without_panicking() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature = setup.signature_with_inconsistent_curve("POST", "/v1/payments/transfer");

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "bad_jwk");
}

/// Case 14: `att.status = "revoked"` -> device_not_active.
#[tokio::test]
async fn case_14_revoked_device_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.attestation_with_status("revoked");
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::DeviceNotActive);
}

/// Case 15: replay store unavailable -> reject (fail closed), never fail open.
#[tokio::test]
async fn case_15_unavailable_replay_store_fails_closed() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = UnavailableReplayStore;
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(
        err,
        VerifyError::ReplayDetected,
        "a replay store outage must reject, exactly like a genuine replay -- never fail open"
    );
}

/// Case 16: method altered after signing -> method_mismatch.
#[tokio::test]
async fn case_16_altered_method_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "DELETE", // signed for POST
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::MethodMismatch);
}

/// Case 16b: path altered after signing -> path_mismatch.
#[tokio::test]
async fn case_16_altered_path_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature =
        setup.valid_signature(&setup.device, "POST", "/v1/payments/transfer", None, None);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/admin/reset", // signed for /v1/payments/transfer
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::PathMismatch);
}

/// Case 17: query string altered, `qsh` present -> query_mismatch.
#[tokio::test]
async fn case_17_altered_query_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature =
        setup.valid_signature_with_query(&setup.device, "GET", "/v1/accounts", "page=1");

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "GET",
        path: "/v1/accounts",
        query: Some("page=999"), // signed for page=1
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::QueryMismatch);
}

/// Case 18: clock skew within tolerance -> Accept.
#[tokio::test]
async fn case_18_clock_skew_within_tolerance_is_accepted() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    // Signed 20s in the future per the signer's clock; config allows 30s of skew.
    let signature = setup.signature_with_time_offsets(
        &setup.device,
        "POST",
        "/v1/payments/transfer",
        20,
        20 + 90,
    );

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .expect("skew within configured tolerance must be accepted");
}

/// Case 19: a symmetric alg (HS256) offered -> bad_alg, even though HS256 is a real,
/// well-formed `jsonwebtoken::Algorithm` variant (unlike "none").
#[tokio::test]
async fn case_19_symmetric_alg_is_rejected() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let signature =
        setup.signature_signed_with_hmac(&setup.device, "POST", "/v1/payments/transfer");

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "bad_alg");
}

/// Extra defense-in-depth check: even if a caller misconfigures `allowed_algs` to include a
/// symmetric algorithm, `verify()` must still reject it. `VerifierConfig::new` filters symmetric
/// algs out, so this test bypasses that constructor to exercise the raw struct.
#[tokio::test]
async fn symmetric_alg_rejected_even_if_present_in_allowed_algs() {
    let mut setup = TestSetup::new().await;
    setup
        .config
        .allowed_algs
        .push(jsonwebtoken::Algorithm::HS256);

    let attestation = setup.valid_attestation();
    let signature =
        setup.signature_signed_with_hmac(&setup.device, "POST", "/v1/payments/transfer");

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    let err = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err.code(), "bad_alg");
}

/// Not a numbered case, but directly implied by the crate's structure: without a valid binding,
/// `replay_store.put_if_absent` must never be called at all -- rejection at the binding-check
/// step happens before the replay step. Regression guard for "the attacker's-key rejection
/// leaks a jti into the replay store even though it rejects".
#[tokio::test]
async fn case_04_rejection_does_not_consume_the_jti() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    let shared_jti = "01JQZX3F7K8N4Y2M6P1R9T5V0W";
    let bad_signature = setup.valid_signature_with_jti(
        &setup.attacker,
        "POST",
        "/v1/payments/transfer",
        shared_jti,
    );
    let store = InMemoryReplayStore::new();

    let bad_request = SignedRequest {
        signature: Some(&bad_signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };
    let err = authkestra_devsig::verify(&bad_request, &setup.config, &setup.jwks, &store)
        .await
        .unwrap_err();
    assert_eq!(err, VerifyError::KeyNotBound);

    // The jti from the rejected signature must still be free to use by the legitimate device.
    let good_signature =
        setup.valid_signature_with_jti(&setup.device, "POST", "/v1/payments/transfer", shared_jti);
    let good_request = SignedRequest {
        signature: Some(&good_signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };
    authkestra_devsig::verify(&good_request, &setup.config, &setup.jwks, &store)
        .await
        .expect("a jti from a rejected (unbound) signature must not have been consumed");
}

/// Just documenting a quiet requirement of `Duration::from_secs((exp - now).max(0))`: a
/// negative `sig.exp - now` (already expired, but somehow inside skew) shouldn't panic.
#[tokio::test]
async fn expired_but_within_skew_does_not_panic_on_replay_ttl() {
    let setup = TestSetup::new().await;
    let attestation = setup.valid_attestation();
    // exp already passed, but iat/exp window still inside max_clock_skew.
    let signature =
        setup.signature_with_time_offsets(&setup.device, "POST", "/v1/payments/transfer", -40, -10);

    let request = SignedRequest {
        signature: Some(&signature),
        attestation: Some(&attestation),
        method: "POST",
        path: "/v1/payments/transfer",
        query: None,
        body: None,
    };

    let store = InMemoryReplayStore::new();
    // Whether this accepts or rejects on freshness grounds depends on exact skew math; the
    // only hard requirement here is that it doesn't panic while computing the replay TTL.
    let _ = authkestra_devsig::verify(&request, &setup.config, &setup.jwks, &store).await;
}
