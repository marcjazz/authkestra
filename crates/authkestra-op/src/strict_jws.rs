//! A **strict** Ed25519 gate layered in front of `jsonwebtoken`'s compact-JWS verification.
//!
//! ## Why this module exists ([authkestra#256](https://github.com/marcjazz/authkestra/issues/256))
//!
//! `jsonwebtoken` 11.0.0's `rust_crypto` backend verifies EdDSA with
//! `ed25519_dalek::Verifier::verify` — the **non-strict** verifier. Non-strict verification never
//! asks whether the public key, or the signature's `R`, is a low-order point, so the triple
//! `(A = identity, R = identity, S = 0)` satisfies `[S]B - [k]A == R` for *every* message: both
//! sides collapse to the identity whatever the challenge scalar `k` is. No private key exists for
//! such a public key — not "is unknown", *does not exist*.
//!
//! In `authkestra-op` the verifying key is attacker-controlled by construction: it arrives as
//! `EnrolStartRequest::public_jwk`, and the enrolment ceremony's entire purpose is to prove
//! possession of the matching private key before minting an attestation bound to its thumbprint.
//! A verifier that accepts a signature under a key nobody holds does not prove possession of
//! anything.
//!
//! ## Relationship to `authkestra-devsig`
//!
//! This is a deliberate **port of `crates/authkestra-devsig/src/eddsa.rs`**
//! (`verify_jws_signature` / `ed25519_verifying_key`, added by #253 for authkestra#242). Two
//! deviations from the original, both intentional:
//!
//! 1. **It is a gate, not a replacement.** `devsig`'s version *is* the verifier and returns
//!    `Ok(bool)`. Here both call sites — [`crate::attestation::verify_challenge_signature`] and
//!    [`crate::client_assertion::verify_client_assertion`] — must also run `jsonwebtoken`'s claim
//!    validation (`exp`, `nbf`, `aud`, the algorithm allow-list). Rather than reimplement that,
//!    this runs *before* `jsonwebtoken::decode` and rejects what strict verification refuses.
//!    Because strict verification rejects a strict superset of what non-strict rejects, gating
//!    first is equivalent to making the whole path strict, with no claim logic duplicated.
//! 2. **It dispatches on the key, not on an `Algorithm` argument.** Both call sites derive the
//!    permitted algorithm from the key (`expected_algorithm` / `assertion_algorithms`), and every
//!    `OctetKeyPair` is decoded as Ed25519 by `DecodingKey::from_jwk` regardless of `crv`. Keying
//!    off "is this an OKP JWK" therefore covers exactly the set of keys that reach the EdDSA
//!    backend. Non-OKP keys are a no-op here and stay entirely with `jsonwebtoken`.
//!
//! No RSA or ECDSA verification is reimplemented in this module.
//!
//! ## Why not fix `jsonwebtoken` instead
//!
//! The backend choice is upstream of authkestra and applies to every `jsonwebtoken` consumer;
//! waiting on it would leave the exploitable path open for however long that takes. Gating only
//! the EdDSA path here is the smallest change that closes it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};

/// Why a strict EdDSA check refused a compact JWS.
///
/// The split mirrors `authkestra-devsig`'s `VerifyFailure` so each call site can map the two
/// cases onto the rejection code its part of the protocol names — **a bad key is not a bad
/// signature**, and reporting a low-order key as `bad_signature` would hide the fact that the
/// *key* is the defect.
#[derive(Debug)]
pub(crate) enum StrictEdDsaRejection {
    /// The verifying key is unusable or unsafe — malformed, wrong curve, or a low-order point.
    Key(String),
    /// The signature is malformed, or was checked strictly and did not verify.
    Signature(String),
}

/// Applies strict Ed25519 verification to `compact_jws` when `jwk` is an OKP key.
///
/// A no-op returning `Ok(())` for every other key type: those never reach `jsonwebtoken`'s EdDSA
/// backend, so there is nothing here to add and their verification is left untouched.
///
/// Callers must still run `jsonwebtoken::decode` afterwards for claim validation; this only
/// removes the signatures strict verification refuses (see the module doc for why gating rather
/// than replacing).
pub(crate) fn ensure_strict_eddsa_signature(
    compact_jws: &str,
    jwk: &Jwk,
) -> Result<(), StrictEdDsaRejection> {
    let params = match &jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(params) => params,
        // Not an OKP key, so `DecodingKey::from_jwk` will not produce an Ed25519 key and the
        // EdDSA backend is unreachable. Nothing to gate.
        _ => return Ok(()),
    };

    if params.curve != EllipticCurve::Ed25519 {
        return Err(StrictEdDsaRejection::Key(format!(
            "Ed25519 is the only supported OKP curve, got {:?}",
            params.curve
        )));
    }

    let key = ed25519_verifying_key(&params.x)?;

    // `.` splits are done here rather than reusing the caller's parse so this function is
    // self-contained and cannot be desynchronised from how the signing input was formed.
    let mut parts = compact_jws.rsplitn(2, '.');
    let signature_b64 = parts
        .next()
        .ok_or_else(|| StrictEdDsaRejection::Signature("compact jws has no signature".into()))?;
    let signing_input = parts.next().ok_or_else(|| {
        StrictEdDsaRejection::Signature("compact jws is not header.payload.signature".into())
    })?;

    let signature_bytes = URL_SAFE_NO_PAD.decode(signature_b64).map_err(|e| {
        StrictEdDsaRejection::Signature(format!("signature is not valid base64url: {e}"))
    })?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| {
        StrictEdDsaRejection::Signature(format!(
            "an Ed25519 signature must be exactly 64 bytes, got {}",
            signature_bytes.len()
        ))
    })?;

    match key.verify_strict(signing_input.as_bytes(), &signature) {
        Ok(()) => Ok(()),
        Err(_) => {
            // `verify_strict` folds "the equation did not hold" and "R is a low-order point" into
            // a single opaque error. Recompute the latter so operators can tell routine signature
            // failures from an attempted low-order forgery, which is an attack signal and not
            // noise. `VerifyingKey::from_bytes` is reused purely as a compressed-Edwards-point
            // decoder here — `R` has the same encoding as a public key, and `is_weak()` is the
            // only small-order predicate `ed25519-dalek` exposes publicly.
            let r_is_small_order = VerifyingKey::from_bytes(
                signature_bytes[..32]
                    .try_into()
                    .expect("a 64-byte Ed25519 signature always yields a 32-byte R"),
            )
            .is_ok_and(|r| r.is_weak());

            if r_is_small_order {
                tracing::warn!(
                    "rejecting EdDSA signature: its R component is a low-order point — strict \
                     verification refuses these because they carry no proof of possession \
                     (authkestra#256)"
                );
            } else {
                tracing::debug!("EdDSA signature did not verify under strict verification");
            }

            Err(StrictEdDsaRejection::Signature(
                "EdDSA signature did not verify under strict verification".into(),
            ))
        }
    }
}

/// Decodes an Ed25519 verifying key from an OKP `x`, **rejecting low-order ("weak") keys**.
///
/// Duplicated deliberately from the equivalent step in `parse_public_jwk` rather than assumed:
/// this module is the last gate before the non-strict backend, and it must hold on its own merits
/// even if a future call site reaches it without having gone through `parse_public_jwk` first.
fn ed25519_verifying_key(x_b64: &str) -> Result<VerifyingKey, StrictEdDsaRejection> {
    authkestra_crypto_util::parse_ed25519_verifying_key_strict(x_b64).map_err(|e| {
        if matches!(e, authkestra_crypto_util::EdDsaKeyError::LowOrderPoint) {
            tracing::warn!(
                "rejecting Ed25519 key: it is a low-order (weak) point, for which no private key \
                 exists — a signature under it would prove possession of nothing, so it is \
                 refused before verification is even attempted (authkestra#256)"
            );
        }
        StrictEdDsaRejection::Key(e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    /// The Ed25519 identity point: the canonical *universal* low-order vector.
    const IDENTITY: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn okp_jwk(crv: &str, x: &[u8]) -> Jwk {
        serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": crv,
            "x": b64(x),
        }))
        .expect("test jwk must parse")
    }

    fn jws(signing_input: &str, signature: &[u8]) -> String {
        format!("{signing_input}.{}", b64(signature))
    }

    /// Pins that the universal low-order forgery — the one the **non-strict** verifier accepts —
    /// is refused here.
    ///
    /// Note what this does *not* pin, corrected after review of #265: it does not distinguish
    /// `verify_strict` from `Verifier::verify`. Measured — swapping the `verify_strict` call for
    /// `Verifier::verify` leaves the whole suite green. The tell is this test's own assertion: it
    /// expects a `Key(low-order)` rejection, which `ed25519_verifying_key`'s `is_weak()` emits
    /// *before* the signature check runs at all.
    ///
    /// That gap is not worth closing with code. The only inputs the two verifiers disagree on are
    /// a small-order `A` — already refused by `is_weak()` — and a small-order `R` under a
    /// non-small-order `A`, which plain `verify` also rejects because `expected_R` will not match.
    /// So `verify_strict` is genuine belt-and-braces here, and no end-to-end test can tell the two
    /// apart. Keeping it is still correct: it is the documented-strict API, and it stops the
    /// guarantee resting solely on `is_weak()`.
    #[test]
    fn strict_verification_rejects_the_universal_forgery_non_strict_accepts() {
        let weak = VerifyingKey::from_bytes(&IDENTITY).expect("identity is a valid Edwards point");
        assert!(weak.is_weak(), "the identity point must be low-order");

        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&IDENTITY);

        assert!(
            weak.verify(b"aGVhZGVy.cGF5bG9hZA", &Signature::from_bytes(&forged))
                .is_ok(),
            "precondition: the NON-strict verifier accepts this forgery — if this ever fails, \
             upstream changed and this test no longer proves what it claims"
        );

        let err = ensure_strict_eddsa_signature(
            &jws("aGVhZGVy.cGF5bG9hZA", &forged),
            &okp_jwk("Ed25519", &IDENTITY),
        )
        .expect_err("the universal forgery must be refused");

        // A bad KEY, not a bad signature: the key is the defect here.
        assert!(
            matches!(&err, StrictEdDsaRejection::Key(m) if m.contains("low-order")),
            "expected a Key(low-order) rejection, got {err:?}"
        );
    }

    /// The `crv`-confusion bypass: an OKP key whose `crv` is not Ed25519 still reaches the EdDSA
    /// backend, so it must be refused here too.
    #[test]
    fn strict_verification_rejects_a_non_ed25519_okp_curve() {
        let mut forged = [0u8; 64];
        forged[..32].copy_from_slice(&IDENTITY);

        let err = ensure_strict_eddsa_signature(
            &jws("aGVhZGVy.cGF5bG9hZA", &forged),
            &okp_jwk("P-256", &IDENTITY),
        )
        .expect_err("a non-Ed25519 OKP curve must be refused");

        assert!(
            matches!(&err, StrictEdDsaRejection::Key(m) if m.contains("only supported OKP curve")),
            "expected a Key(wrong curve) rejection, got {err:?}"
        );
    }

    /// Positive control: a gate that rejects everything is not a gate.
    #[test]
    fn strict_verification_accepts_a_genuine_signature() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let key = signing.verifying_key();
        assert!(!key.is_weak());

        let signing_input = "aGVhZGVy.cGF5bG9hZA";
        let genuine = signing.sign(signing_input.as_bytes());

        ensure_strict_eddsa_signature(
            &jws(signing_input, &genuine.to_bytes()),
            &okp_jwk("Ed25519", key.as_bytes()),
        )
        .expect("a genuine Ed25519 signature must pass the strict gate");
    }

    /// A genuine key with someone else's signature is a SIGNATURE failure, not a key failure —
    /// the classification split this module's error type exists for.
    #[test]
    fn a_wrong_signature_under_a_good_key_is_classified_as_a_signature_failure() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let other = SigningKey::from_bytes(&[9u8; 32]);

        let signing_input = "aGVhZGVy.cGF5bG9hZA";
        let wrong = other.sign(signing_input.as_bytes());

        let err = ensure_strict_eddsa_signature(
            &jws(signing_input, &wrong.to_bytes()),
            &okp_jwk("Ed25519", signing.verifying_key().as_bytes()),
        )
        .expect_err("a signature from a different key must be refused");

        assert!(
            matches!(err, StrictEdDsaRejection::Signature(_)),
            "expected a Signature rejection, got {err:?}"
        );
    }

    /// Non-OKP keys must pass through untouched — this module must not start refusing EC or RSA
    /// keys it has no business inspecting.
    #[test]
    fn non_okp_keys_are_a_no_op() {
        let ec: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        }))
        .unwrap();

        ensure_strict_eddsa_signature("aGVhZGVy.cGF5bG9hZA.c2ln", &ec)
            .expect("a non-OKP key must be left entirely to jsonwebtoken");
    }
}
