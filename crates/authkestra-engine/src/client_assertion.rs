//! Client-side minting of `private_key_jwt` client assertions (RFC 7523
//! §2.2, OIDC Core §9).
//!
//! This is the mirror image of `authkestra_op::client_assertion`, which
//! *verifies* an inbound assertion at the OP — that module cannot live here
//! (it needs `ClientRegistration`/replay-store types this crate has no
//! business knowing about), but this crate is the one place both halves can
//! share without a dependency cycle: `authkestra-op` already depends on
//! `authkestra-engine`, never the other way around. So the two constants
//! below are defined exactly once, here, and `authkestra-op` re-exports them
//! rather than keeping its own copies — the assertion-type URN and the
//! maximum assertion lifetime literally cannot drift between the client side
//! ([`crate::flow::ClientCredentialsFlow::new_private_key_jwt`]) and this
//! workspace's own OP.
//!
//! See [`mint_client_assertion`] for the minting logic itself.

use crate::auth::error::AuthError;
use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

/// The `client_assertion_type` value RFC 7523 §2.2 requires when presenting
/// a `private_key_jwt` assertion at a token endpoint.
pub const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Upper bound on how far in the future a minted assertion's `exp` may sit.
///
/// RFC 7523 §3 requires `exp` to be present and unexpired but sets no
/// ceiling, and an assertion is a bearer credential for its whole lifetime —
/// a decade-long one would be a permanent password in JWT clothing. This
/// crate's own OP (`authkestra_op::client_assertion`) enforces the identical
/// bound on the verifying side, so minting anything longer-lived here would
/// only produce assertions that OP (or any other conformant verifier
/// applying the same discipline) rejects for a reason invisible from the
/// client side.
pub const MAX_CLIENT_ASSERTION_LIFETIME_SECS: i64 = 300;

/// The claims RFC 7523 §3 requires a `private_key_jwt` assertion to carry.
///
/// `iss` and `sub` are both the client's own `client_id` — RFC 7523 §3
/// points 1-2 require the assertion to be self-issued for the client it
/// authenticates, and `authkestra_op::client_assertion::verify_client_assertion`
/// rejects anything else.
#[derive(Debug, Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    jti: String,
    exp: i64,
    iat: i64,
}

/// Mints a fresh `private_key_jwt` client assertion authenticating
/// `client_id` to `audience` (the token endpoint URL, per RFC 7523 §3).
///
/// A fresh `jti` (UUIDv4) is generated on every call: reusing one across
/// calls would hand a replay-tracking verifier — such as
/// `authkestra_op::client_assertion::ClientAssertionStore` — a second
/// presentation of an id it already spent, which is indistinguishable from
/// an actual replay and would be rejected.
///
/// `lifetime_secs` is clamped to `1..=MAX_CLIENT_ASSERTION_LIFETIME_SECS`
/// rather than trusted verbatim: a caller-supplied value above that ceiling
/// would only mint an assertion this workspace's own OP (or any verifier
/// enforcing the same bound) refuses, for a reason invisible from here: it's
/// cheaper to clamp than to hand back an assertion doomed to fail
/// verification for a reason invisible at the call site.
#[tracing::instrument(skip(encoding_key))]
pub fn mint_client_assertion(
    client_id: &str,
    audience: &str,
    encoding_key: &EncodingKey,
    alg: Algorithm,
    kid: Option<&str>,
    lifetime_secs: i64,
) -> Result<String, AuthError> {
    let lifetime_secs = lifetime_secs.clamp(1, MAX_CLIENT_ASSERTION_LIFETIME_SECS);
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(lifetime_secs);

    let claims = AssertionClaims {
        iss: client_id,
        sub: client_id,
        aud: audience,
        jti: uuid::Uuid::new_v4().to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_string);

    let assertion = jsonwebtoken::encode(&header, &claims, encoding_key).map_err(|e| {
        tracing::error!(client_id = %client_id, error = %e, "failed to sign private_key_jwt client assertion");
        AuthError::Token(e.to_string())
    })?;

    tracing::debug!(client_id = %client_id, audience = %audience, "minted private_key_jwt client assertion");
    Ok(assertion)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::Value;

    /// Throwaway Ed25519 private key (PKCS#8 PEM), test-only. Same key used
    /// in `crate::token::tests`, generated with
    /// `openssl genpkey -algorithm ed25519`.
    const TEST_ED25519_PRIVATE_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKIPR2jojpdobYr1M/pjIRuMONpZGYQ+y5yxSqKX9T9/
-----END PRIVATE KEY-----";

    fn decode_parts(jwt: &str) -> (Value, Value) {
        let mut parts = jwt.split('.');
        let header_b64 = parts.next().unwrap();
        let payload_b64 = parts.next().unwrap();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        (header, payload)
    }

    #[test]
    fn mints_an_assertion_with_iss_sub_client_id_and_correct_aud() {
        let key = EncodingKey::from_ed_pem(TEST_ED25519_PRIVATE_KEY_PEM).unwrap();
        let jwt = mint_client_assertion(
            "svc-1",
            "https://auth.example.com/token",
            &key,
            Algorithm::EdDSA,
            None,
            60,
        )
        .unwrap();

        let (header, payload) = decode_parts(&jwt);
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(payload["iss"], "svc-1");
        assert_eq!(payload["sub"], "svc-1");
        assert_eq!(payload["aud"], "https://auth.example.com/token");
    }

    #[test]
    fn mints_a_fresh_jti_every_call() {
        let key = EncodingKey::from_ed_pem(TEST_ED25519_PRIVATE_KEY_PEM).unwrap();
        let jwt_a = mint_client_assertion(
            "svc-1",
            "https://auth.example.com/token",
            &key,
            Algorithm::EdDSA,
            None,
            60,
        )
        .unwrap();
        let jwt_b = mint_client_assertion(
            "svc-1",
            "https://auth.example.com/token",
            &key,
            Algorithm::EdDSA,
            None,
            60,
        )
        .unwrap();

        let (_, payload_a) = decode_parts(&jwt_a);
        let (_, payload_b) = decode_parts(&jwt_b);

        let jti_a = payload_a["jti"].as_str().unwrap();
        let jti_b = payload_b["jti"].as_str().unwrap();
        assert!(!jti_a.is_empty());
        assert!(!jti_b.is_empty());
        assert_ne!(jti_a, jti_b, "each minted assertion must carry its own jti");
    }

    #[test]
    fn clamps_a_lifetime_beyond_the_max_to_the_max() {
        let key = EncodingKey::from_ed_pem(TEST_ED25519_PRIVATE_KEY_PEM).unwrap();
        let jwt = mint_client_assertion(
            "svc-1",
            "https://auth.example.com/token",
            &key,
            Algorithm::EdDSA,
            None,
            MAX_CLIENT_ASSERTION_LIFETIME_SECS * 100,
        )
        .unwrap();

        let (_, payload) = decode_parts(&jwt);
        let exp = payload["exp"].as_i64().unwrap();
        let iat = payload["iat"].as_i64().unwrap();
        assert!(
            exp - iat <= MAX_CLIENT_ASSERTION_LIFETIME_SECS,
            "exp must never be minted further out than MAX_CLIENT_ASSERTION_LIFETIME_SECS, \
             got a lifetime of {} seconds",
            exp - iat
        );
    }

    #[test]
    fn stamps_the_given_kid_onto_the_header() {
        let key = EncodingKey::from_ed_pem(TEST_ED25519_PRIVATE_KEY_PEM).unwrap();
        let jwt = mint_client_assertion(
            "svc-1",
            "https://auth.example.com/token",
            &key,
            Algorithm::EdDSA,
            Some("key-1"),
            60,
        )
        .unwrap();

        let (header, _) = decode_parts(&jwt);
        assert_eq!(header["kid"], "key-1");
    }
}
