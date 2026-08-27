//! Compact-JWS signature verification, with a **strict** Ed25519 path of this crate's own.
//!
//! ## Why this module exists ([authkestra#242](https://github.com/marcjazz/authkestra/issues/242))
//!
//! `jsonwebtoken` 11.0.0's `rust_crypto` backend verifies EdDSA with
//! `ed25519_dalek::Verifier::verify` — the **non-strict** verifier (see
//! `jsonwebtoken-11.0.0/src/crypto/rust_crypto/eddsa.rs`). Non-strict verification never asks
//! whether the public key, or the signature's `R`, is a low-order point, so the triple
//! `(A = identity, R = identity, S = 0)` satisfies the verification equation `[S]B - [k]A == R`
//! for *every* message: both sides collapse to the identity whatever the challenge scalar `k` is.
//! No private key exists for such a public key — not "is unknown", *does not exist*.
//!
//! That is fatal for this crate specifically, because here the verifying key is **not** trusted
//! input: it travels in the request, inside the `X-Signature` protected header's embedded `jwk`.
//! The binding check ties that `jwk` to the attestation's `cnf.jkt`, but a low-order key
//! thumbprints exactly like a real one, so an attacker who gets one enrolled passes the binding
//! check honestly and then needs no secret at all to sign. Per-request proof of possession — the
//! entire reason `authkestra-devsig` exists — would be gone.
//!
//! The same strict path is applied to the attestation's issuer key. That key comes from the
//! cached Issuer JWKS, which is a great deal more trustworthy than a key arriving in the request,
//! so this is defence in depth rather than a live exposure; but "more trustworthy" is not
//! "unforgeable", and a low-order key reaching a verifier's JWKS (compromised issuer, hostile
//! mirror, buggy rotation tooling) would let anyone mint attestations for any subject.
//!
//! ## Why not fix `jsonwebtoken` instead
//!
//! The backend choice is upstream of authkestra and applies to every `jsonwebtoken` consumer;
//! waiting on it would leave the exploitable path open for however long that takes. Overriding
//! only the EdDSA branch here is the smallest change that closes it, and
//! `canary_upstream_jsonwebtoken_still_verifies_eddsa_non_strictly` in `tests/conformance.rs`
//! will fail loudly if upstream ever adopts strict verification, so this workaround cannot
//! quietly outlive its reason.
//!
//! Every non-EdDSA algorithm is still delegated to `jsonwebtoken::crypto::verify` unchanged —
//! this module deliberately does not reimplement RSA or ECDSA verification.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{crypto, Algorithm, DecodingKey};

/// Why a signature check could not be *carried out*, as opposed to a signature that was checked
/// and did not verify (which is an `Ok(false)`, not an error).
///
/// The split exists so each call site can map the two cases onto the rejection code its part of
/// the algorithm names — a bad key is not a bad signature, and reporting a low-order key as
/// `bad_signature` would hide the fact that the *key* is the defect.
#[derive(Debug)]
pub enum VerifyFailure {
    /// The verifying key is unusable or unsafe — malformed, or a low-order Ed25519 point.
    Key(String),
    /// The backend could not run the check at all (e.g. a signature segment that is not
    /// well-formed base64url, or is not 64 bytes for Ed25519).
    Backend(String),
}

/// Verifies a compact JWS signature segment against `jwk`, using strict verification for EdDSA
/// and `jsonwebtoken`'s own backend for every other algorithm.
///
/// `decoding_key` must already have been derived from `jwk`; both are taken because the EdDSA
/// path needs the raw `x` coordinate (to run the low-order check that `DecodingKey` gives no
/// access to) while every other path needs the `DecodingKey`.
pub fn verify_jws_signature(
    alg: Algorithm,
    jwk: &Jwk,
    decoding_key: &DecodingKey,
    signature_b64: &str,
    signing_input: &[u8],
) -> Result<bool, VerifyFailure> {
    if alg != Algorithm::EdDSA {
        return crypto::verify(signature_b64, signing_input, decoding_key, alg)
            .map_err(|e| VerifyFailure::Backend(e.to_string()));
    }

    let key = ed25519_verifying_key(jwk)?;

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| VerifyFailure::Backend(format!("signature is not valid base64url: {e}")))?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        VerifyFailure::Backend(format!(
            "an Ed25519 signature must be exactly 64 bytes, got {}",
            signature_bytes.len()
        ))
    })?;

    match key.verify_strict(signing_input, &signature) {
        Ok(()) => Ok(true),
        Err(_) => {
            // `verify_strict` folds "the equation did not hold" and "R is a low-order point" into
            // a single opaque error. Recompute the latter so operators can tell routine signature
            // failures from an attempted low-order forgery, which is an attack signal and not
            // noise. `VerifyingKey::from_bytes` is reused purely as a compressed-Edwards-point
            // decoder here -- `R` is the same encoding as a public key, and `is_weak()` is the
            // only small-order predicate `ed25519-dalek` exposes publicly.
            let r_is_small_order = VerifyingKey::from_bytes(
                signature_bytes[..32]
                    .try_into()
                    .expect("a 64-byte Ed25519 signature always yields a 32-byte R"),
            )
            .is_ok_and(|r| r.is_weak());
            if r_is_small_order {
                tracing::warn!(
                    target: "authkestra_devsig",
                    "rejecting EdDSA signature: its R component is a low-order point — strict \
                     verification refuses these because they carry no proof of possession \
                     (authkestra#242)"
                );
            } else {
                tracing::debug!(
                    target: "authkestra_devsig",
                    "EdDSA signature did not verify under strict verification"
                );
            }
            Ok(false)
        }
    }
}

/// Extracts an Ed25519 verifying key from `jwk`, **rejecting low-order ("weak") keys**.
///
/// This is the check whose absence authkestra#242 reports: it must run before any verification
/// attempt, so that the key is rejected on its own merits rather than on whichever signature
/// bytes happened to accompany it.
fn ed25519_verifying_key(jwk: &Jwk) -> Result<VerifyingKey, VerifyFailure> {
    let params = match &jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(params) => params,
        _ => return Err(VerifyFailure::Key("EdDSA requires an OKP key".to_string())),
    };
    if params.curve != EllipticCurve::Ed25519 {
        return Err(VerifyFailure::Key(format!(
            "EdDSA requires the Ed25519 curve, got {:?}",
            params.curve
        )));
    }

    let x = URL_SAFE_NO_PAD
        .decode(&params.x)
        .map_err(|e| VerifyFailure::Key(format!("OKP \"x\" is not valid base64url: {e}")))?;
    let x: [u8; 32] = x.as_slice().try_into().map_err(|_| {
        VerifyFailure::Key(format!(
            "an Ed25519 public key must be exactly 32 bytes, got {}",
            x.len()
        ))
    })?;

    let key = VerifyingKey::from_bytes(&x)
        .map_err(|_| VerifyFailure::Key("OKP \"x\" is not a valid Ed25519 point".to_string()))?;

    if key.is_weak() {
        tracing::warn!(
            target: "authkestra_devsig",
            "rejecting Ed25519 key: it is a low-order (weak) point, for which no private key \
             exists — a signature under it would prove possession of nothing, so it is refused \
             before verification is even attempted (authkestra#242)"
        );
        return Err(VerifyFailure::Key(
            "Ed25519 public key is a low-order point; no private key exists for it, so a \
             signature under it proves nothing"
                .to_string(),
        ));
    }

    Ok(key)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    /// The identity point: the canonical universal low-order vector.
    const IDENTITY: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    /// Pins `verify_strict` over the non-strict `Verifier::verify`.
    ///
    /// Raised in review of #242: swapping `verify_strict` for `Verifier::verify`
    /// in [`super::verify_jws_signature`] leaves the whole conformance suite
    /// green, so nothing pinned the strict call itself. That is expected rather
    /// than alarming — [`super::ed25519_verifying_key`]'s `is_weak()` gate
    /// rejects a small-order `A` *before* verification runs, and producing a
    /// small-order `R` that satisfies the equation under a non-small-order `A`
    /// would require solving a discrete log. So there is no reachable
    /// end-to-end input that distinguishes the two verifiers.
    ///
    /// The distinguishing input therefore has to be a small-order *key*, which
    /// means calling dalek directly here, below that gate. This is the pair the
    /// two verifiers genuinely disagree about, and it is what makes the strict
    /// call load-bearing rather than decorative: without it, a future refactor
    /// could drop `verify_strict` and CI would stay green.
    #[test]
    fn strict_verification_rejects_a_low_order_key_that_non_strict_accepts() {
        let weak = VerifyingKey::from_bytes(&IDENTITY).expect("identity is a valid Edwards point");
        assert!(weak.is_weak(), "the identity point must be low-order");

        // (R = identity, S = 0): both sides of [S]B - [k]A == R collapse to the
        // identity for every challenge scalar, so this verifies under ANY message.
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&IDENTITY);
        let forged = Signature::from_bytes(&forged);

        assert!(
            weak.verify(b"authkestra", &forged).is_ok(),
            "precondition: the NON-strict verifier accepts this forgery — if this ever fails, \
             upstream changed and this test no longer proves what it claims"
        );
        assert!(
            weak.verify_strict(b"authkestra", &forged).is_err(),
            "verify_strict must reject a low-order key that non-strict accepts"
        );
    }

    /// Positive control: a fix that rejects everything is not a fix.
    #[test]
    fn strict_verification_still_accepts_a_genuine_signature() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let key = signing.verifying_key();
        assert!(!key.is_weak());

        let genuine = signing.sign(b"authkestra");
        assert!(key.verify_strict(b"authkestra", &genuine).is_ok());
    }
}
