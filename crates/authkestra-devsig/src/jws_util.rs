//! Low-level compact-JWS handling shared by attestation and signature verification.
//!
//! `jsonwebtoken`'s typed API is not safe to hand a fully-untrusted header/JWK straight into,
//! for two independent reasons that both matter here:
//!
//! 1. `jsonwebtoken::Algorithm`'s `Deserialize` impl only knows the algorithm names it supports
//!    and hard-fails — a generic, unstructured error — on anything else, including the literal
//!    string `"none"`. There is no catch-all variant. Handed to a typed parse, `alg: "none"` and
//!    `alg: "not-a-real-algorithm"` are indistinguishable from a corrupted token, which would
//!    collapse the distinct `bad_alg` rejection this scheme requires into a generic `malformed`.
//! 2. `jsonwebtoken::jwk::Jwk` silently drops any JSON member it doesn't have a field for —
//!    including a private key component `"d"` smuggled onto an otherwise-public-looking JWK.
//!    A naive `serde_json::from_value::<Jwk>(embedded)` "succeeds" even when the attacker
//!    included a private scalar, because the typed struct simply has no field to put it in and
//!    serde drops what it doesn't recognize.
//!
//! Both are handled the same way: peek at the raw JSON *before* it ever reaches `jsonwebtoken`'s
//! typed API.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::Algorithm;
use serde_json::Value;
use subtle::ConstantTimeEq;

use crate::config::is_symmetric;
use crate::error::VerifyError;

/// The three raw (still base64url-encoded) segments of a compact JWS.
#[non_exhaustive]
pub struct RawJws<'a> {
    pub header_b64: &'a str,
    pub payload_b64: &'a str,
    pub signature_b64: &'a str,
}

/// Splits `token` into its three compact-JWS segments. Rejects anything that isn't exactly
/// `header.payload.signature`.
pub fn split_compact(token: &str) -> Result<RawJws<'_>, VerifyError> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) if !h.is_empty() && !s.is_empty() => Ok(RawJws {
            header_b64: h,
            payload_b64: p,
            signature_b64: s,
        }),
        _ => Err(VerifyError::Malformed(
            "expected exactly 3 non-empty dot-separated compact-JWS segments (header, payload, signature)"
                .to_string(),
        )),
    }
}

/// Base64url-decodes a segment and parses it as JSON.
pub fn decode_json_segment(segment: &str) -> Result<Value, VerifyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| VerifyError::Malformed(format!("invalid base64url: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| VerifyError::Malformed(format!("invalid JSON: {e}")))
}

/// Reads the raw `alg` field out of a JOSE header, before any typed parsing, and checks it
/// against `allowed_algs`.
///
/// This is what turns `alg: "none"` and `alg: "HS256"` into `bad_alg` rather than `malformed`,
/// and it hard-rejects the whole symmetric family even if a caller's `allowed_algs` was
/// misconfigured to include one — asymmetric-only is not a suggestion for a scheme whose private
/// key never leaves the signing device.
pub fn parse_and_check_alg(
    header: &Value,
    allowed_algs: &[Algorithm],
) -> Result<Algorithm, VerifyError> {
    let raw_alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| VerifyError::Malformed("header missing alg".to_string()))?;

    if raw_alg.eq_ignore_ascii_case("none") {
        return Err(VerifyError::BadAlg(
            "alg \"none\" is never allowed".to_string(),
        ));
    }

    let alg: Algorithm = raw_alg
        .parse()
        .map_err(|_| VerifyError::BadAlg(format!("unsupported alg {raw_alg:?}")))?;

    if is_symmetric(alg) {
        return Err(VerifyError::BadAlg(format!(
            "{alg:?} is a symmetric algorithm; this scheme is asymmetric-only because the \
             device's private key never leaves the device"
        )));
    }

    if !allowed_algs.contains(&alg) {
        return Err(VerifyError::BadAlg(format!(
            "{alg:?} is not in the configured allow-list"
        )));
    }

    Ok(alg)
}

/// The set of JWK member names that only ever appear on a *private* key (RFC 7518 §6.2.2 for
/// EC, §6.3.2 for RSA, plus the symmetric `k`). `jsonwebtoken::jwk::Jwk` has no fields for any of
/// these — it silently drops unknown JSON members, including `d` — so this check must run
/// against the raw JSON, not the typed struct.
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "k"];

/// Rejects a JWK JSON object that carries any private-key component.
pub fn reject_private_jwk_members(jwk_json: &Value) -> Result<(), VerifyError> {
    if let Some(obj) = jwk_json.as_object() {
        for member in PRIVATE_JWK_MEMBERS {
            if obj.contains_key(*member) {
                return Err(VerifyError::BadJwk(format!(
                    "embedded jwk contains private component \"{member}\" — never trust a \
                     caller-supplied private key"
                )));
            }
        }
    }
    Ok(())
}

/// Constant-time string equality. Used for the thumbprint binding check and the body/query hash
/// comparisons.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    // Compare over fixed-width byte slices; a length mismatch alone is not (and cannot be made)
    // constant-time in this implementation, but leaking "the lengths differ" reveals nothing an
    // attacker doesn't already know (thumbprints and hex hashes have fixed, predictable
    // lengths), unlike leaking a valid prefix would.
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
