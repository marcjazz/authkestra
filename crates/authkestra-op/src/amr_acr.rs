//! `acr`/`amr` claim derivation for issued ID tokens (OIDC Core §2).
//!
//! `authkestra_engine::Engine::authenticate` is the only place that knows
//! which [`AuthMethod`](authkestra_engine::auth::AuthMethod) actually ran —
//! the primary one, and (if the caller completed one) a step-up. It has no
//! reason to know about OIDC claim vocabulary, so it stamps that fact onto
//! [`Identity::attributes`] instead, under the
//! [`IDENTITY_ATTR_AMR`](authkestra_engine::auth::IDENTITY_ATTR_AMR) /
//! [`IDENTITY_ATTR_STEP_UP_SATISFIED`](authkestra_engine::auth::IDENTITY_ATTR_STEP_UP_SATISFIED)
//! keys — the same established idiom `identity.attributes["nonce"]` already
//! uses to thread flow-local data through `Identity` without changing its
//! shape (see `authkestra_engine::flow::oauth2`). This module is the other
//! end: it turns those attributes into the two standard OIDC ID token
//! claims when an issued token's identity carries them.
//!
//! See `docs/rfc-006-acr-amr-claims.md` for the full design rationale.
//!
//! ## AMR value set
//!
//! `authkestra-engine`'s internal auth-method names (`"password"`, `"totp"`,
//! `"webauthn"`) are remapped to the wire values below, moving closer to the
//! IANA registry in RFC 8176 where a value already fits it exactly:
//!
//! - `"password"` → [`AMR_PASSWORD`] (`"pwd"`, RFC 8176's canonical token).
//! - `"totp"` stays `"totp"`: RFC 8176's closest generic value is `"otp"`,
//!   which doesn't distinguish TOTP from HOTP or a mailed/SMS code. This
//!   engine only ever implements TOTP, so the specific, unambiguous name is
//!   more informative to a relying party than the vaguer registry term — and
//!   the registry is explicitly extensible (RFC 8176 §2), not closed.
//! - `"webauthn"` stays `"webauthn"`: RFC 8176 has `"hwk"` (hardware key)
//!   and `"swk"` (software key), but this crate's WebAuthn integration
//!   doesn't distinguish a roaming authenticator from a platform one, so
//!   asserting either would overclaim what was actually verified.
//!   `"webauthn"` names the actual mechanism without guessing.
//! - [`AMR_MFA_MARKER`] (RFC 8176's own generic multi-factor marker,
//!   `"mfa"`) is appended whenever [`ACR_MFA`] applies (see below),
//!   mirroring how several production IdPs report both the constituent
//!   method(s) and this summary value together.
//! - Any other internal method name (a custom
//!   [`AuthMethod`](authkestra_engine::auth::AuthMethod) an integrator
//!   registered) passes through unchanged — this crate has no way to know
//!   what it should map to, and passing it through verbatim is more honest
//!   than dropping it.
//!
//! ## ACR scheme
//!
//! `authkestra-engine`'s step-up model is binary — primary auth, or
//! primary+step-up — so `acr` is too: exactly two self-issued URN values,
//! [`ACR_SINGLE_FACTOR`] and [`ACR_MFA`]. This is deliberately *not* a NIST
//! SP 800-63 AAL1/2/3 ladder or an eIDAS LoA scheme: this engine cannot back
//! a claim that specific (no phishing-resistance attestation, no identity
//! proofing tier, no re-authentication/`max_age` freshness tracking), and a
//! relying party parsing an AAL-shaped string that doesn't mean what AAL
//! means would be actively misled.
//!
//! An identity whose `attributes` carry no `amr` at all — e.g. one that
//! never passed through `Engine::authenticate` at all, such as a federated
//! login handed straight to `handle_authorize` — gets neither claim:
//! omitting `acr`/`amr` is legal per OIDC Core §2 (both OPTIONAL), and
//! asserting a scheme this crate has no evidence for would be worse than
//! saying nothing.

use authkestra_engine::auth::state::{
    Identity, IDENTITY_ATTR_AMR, IDENTITY_ATTR_STEP_UP_SATISFIED,
};
use std::collections::HashMap;

/// `acr` value for a token backed only by primary authentication — no
/// step-up ran, and the primary method itself isn't step-up-equivalent.
pub const ACR_SINGLE_FACTOR: &str = "urn:authkestra:acr:single-factor";

/// `acr` value for a token backed by step-up: either a completed step-up
/// (MFA) challenge on top of primary auth, or a single primary
/// [`AuthMethod`](authkestra_engine::auth::AuthMethod) that itself reports
/// [`is_mfa_equivalent`](authkestra_engine::auth::AuthMethod::is_mfa_equivalent)
/// (e.g. this engine's built-in WebAuthn method used as a primary).
pub const ACR_MFA: &str = "urn:authkestra:acr:mfa";

/// RFC 8176's own generic "multiple-factor" AMR value.
pub const AMR_MFA_MARKER: &str = "mfa";

/// The RFC 8176 token for password authentication — `authkestra-engine`'s
/// internal auth-method name for the same thing is `"password"`.
pub const AMR_PASSWORD: &str = "pwd";

/// Remaps an `authkestra-engine` internal auth-method name to its wire AMR
/// value. See the module docs for the reasoning behind each mapping.
fn internal_method_to_amr(method: &str) -> String {
    match method {
        "password" => AMR_PASSWORD.to_string(),
        other => other.to_string(),
    }
}

/// Builds the `amr`/`acr` entries for an `extra` claims map (as taken by
/// [`TokenManager::issue_id_token_with_extra`](authkestra_engine::token::TokenManager::issue_id_token_with_extra))
/// from the auth-method bookkeeping `Engine::authenticate` stamped onto
/// `identity.attributes`.
///
/// Returns an empty map — no `amr`, no `acr` — when `identity.attributes`
/// carries no [`IDENTITY_ATTR_AMR`] entry, which is the case for any
/// `Identity` that didn't come from `Engine::authenticate` (see the module
/// docs).
pub fn amr_acr_extra_claims(identity: &Identity) -> HashMap<String, serde_json::Value> {
    let mut extra = HashMap::new();

    let Some(raw_amr) = identity.attributes.get(IDENTITY_ATTR_AMR) else {
        return extra;
    };

    let mut amr: Vec<String> = raw_amr
        .split_whitespace()
        .map(internal_method_to_amr)
        .collect();

    let step_up_satisfied = identity
        .attributes
        .get(IDENTITY_ATTR_STEP_UP_SATISFIED)
        .map(|v| v == "true")
        .unwrap_or(false);

    if step_up_satisfied && !amr.iter().any(|m| m == AMR_MFA_MARKER) {
        amr.push(AMR_MFA_MARKER.to_string());
    }

    extra.insert(
        "amr".to_string(),
        serde_json::Value::Array(amr.into_iter().map(serde_json::Value::String).collect()),
    );
    extra.insert(
        "acr".to_string(),
        serde_json::Value::String(
            if step_up_satisfied {
                ACR_MFA
            } else {
                ACR_SINGLE_FACTOR
            }
            .to_string(),
        ),
    );

    extra
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap as StdHashMap;

    fn identity_with(attrs: &[(&str, &str)]) -> Identity {
        let mut attributes = StdHashMap::new();
        for (k, v) in attrs {
            attributes.insert(k.to_string(), v.to_string());
        }
        Identity {
            provider_id: "test".to_string(),
            external_id: "user-1".to_string(),
            email: None,
            username: None,
            attributes,
        }
    }

    #[test]
    fn no_amr_attribute_produces_no_claims() {
        let identity = identity_with(&[]);
        let extra = amr_acr_extra_claims(&identity);
        assert!(extra.is_empty());
    }

    #[test]
    fn primary_only_maps_to_single_factor() {
        let identity = identity_with(&[(IDENTITY_ATTR_AMR, "password")]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["pwd"])));
        assert_eq!(
            extra.get("acr"),
            Some(&serde_json::Value::String(ACR_SINGLE_FACTOR.to_string()))
        );
    }

    #[test]
    fn step_up_completed_adds_the_mfa_marker_and_acr() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, "password totp"),
            (IDENTITY_ATTR_STEP_UP_SATISFIED, "true"),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(
            extra.get("amr"),
            Some(&serde_json::json!(["pwd", "totp", "mfa"]))
        );
        assert_eq!(
            extra.get("acr"),
            Some(&serde_json::Value::String(ACR_MFA.to_string()))
        );
    }

    #[test]
    fn mfa_equivalent_primary_alone_still_reports_acr_mfa() {
        let identity = identity_with(&[
            (IDENTITY_ATTR_AMR, "webauthn"),
            (IDENTITY_ATTR_STEP_UP_SATISFIED, "true"),
        ]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(
            extra.get("amr"),
            Some(&serde_json::json!(["webauthn", "mfa"]))
        );
        assert_eq!(
            extra.get("acr"),
            Some(&serde_json::Value::String(ACR_MFA.to_string()))
        );
    }

    #[test]
    fn unrecognized_internal_method_names_pass_through_verbatim() {
        let identity = identity_with(&[(IDENTITY_ATTR_AMR, "sms_link")]);
        let extra = amr_acr_extra_claims(&identity);
        assert_eq!(extra.get("amr"), Some(&serde_json::json!(["sms_link"])));
    }
}
