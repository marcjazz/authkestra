//! A test-only SET Transmitter: mints Security Event Tokens in the exact wire shape
//! [`authkestra_ssf::SetVerifier`] expects, since nothing in this repo issues SETs yet.
//!
//! Signing is HMAC-SHA256 throughout. That is not a recommendation for production — a real
//! transmitter signs asymmetrically so recipients need no shared secret — but it is what
//! RFC 8935 §2.1's own example transmission uses, it needs no key generation, and every check
//! this suite exercises (`typ`, `alg` allow-listing, issuer, audience, freshness, replay,
//! delivery semantics) is independent of the signature algorithm. The one property that is
//! *not* independent — that a tampered signature is rejected — is covered directly by
//! [`tamper_signature`].

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::{json, Value};

/// The issuer every fixture SET claims, and every fixture verifier expects.
pub const ISSUER: &str = "https://idp.example.com/";
/// The audience every fixture verifier answers to.
pub const AUDIENCE: &str = "https://sp.example.com/caep";
/// The shared secret the fixture transmitter signs with.
pub const SECRET: &[u8] = b"a-test-only-shared-secret-for-hs256-signing";
/// A fixed "now" so freshness assertions do not depend on the wall clock.
pub const NOW: i64 = 1_700_000_000;

/// The decoding key matching [`SECRET`].
pub fn decoding_key() -> DecodingKey {
    DecodingKey::from_secret(SECRET)
}

/// A minimal, valid claims set carrying one CAEP Session Revoked event.
pub fn session_revoked_claims() -> Value {
    json!({
        "iss": ISSUER,
        "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
        "iat": NOW,
        "aud": AUDIENCE,
        "events": {
            authkestra_ssf::EVENT_TYPE_SESSION_REVOKED: {
                "subject": { "format": "opaque", "id": "dMTlD|1600802906" },
                "initiating_entity": "policy",
                "event_timestamp": NOW - 10
            }
        }
    })
}

/// Signs `claims` with `typ: secevent+jwt` and `alg: HS256`.
pub fn sign(claims: &Value) -> String {
    sign_with(Some("secevent+jwt"), Algorithm::HS256, None, claims)
}

/// Signs `claims` with an explicit `typ`, `alg` and `kid`, for the negative cases.
pub fn sign_with(typ: Option<&str>, alg: Algorithm, kid: Option<&str>, claims: &Value) -> String {
    let header = Header {
        typ: typ.map(str::to_string),
        kid: kid.map(str::to_string),
        ..Header::new(alg)
    };
    encode(&header, claims, &EncodingKey::from_secret(SECRET)).expect("fixture SET must encode")
}

/// Builds the unsecured JWT of RFC 8417 §2.4: `alg: none`, empty signature segment.
pub fn unsecured(claims: &Value) -> String {
    let header =
        URL_SAFE_NO_PAD.encode(json!({ "typ": "secevent+jwt", "alg": "none" }).to_string());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

/// Replaces the signature segment with a different, well-formed base64url string.
pub fn tamper_signature(token: &str) -> String {
    let (signing_input, signature) = token
        .rsplit_once('.')
        .expect("a compact JWS has 3 segments");
    let mut bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .expect("fixture signatures are base64url");
    bytes[0] ^= 0xff;
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// Replaces the `events` claim of `claims` with `events`.
pub fn with_events(mut claims: Value, events: Value) -> Value {
    claims
        .as_object_mut()
        .expect("claims are a JSON object")
        .insert("events".to_string(), events);
    claims
}

/// Sets (or, with `Value::Null`, removes) a top-level claim.
pub fn with_claim(mut claims: Value, name: &str, value: Value) -> Value {
    let object = claims.as_object_mut().expect("claims are a JSON object");
    if value.is_null() {
        object.remove(name);
    } else {
        object.insert(name.to_string(), value);
    }
    claims
}
