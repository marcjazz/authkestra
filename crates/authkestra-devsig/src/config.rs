//! Verifier configuration.

use std::collections::HashSet;
use std::time::Duration;

use jsonwebtoken::Algorithm;

/// Static configuration for [`crate::verify`].
///
/// `alg` never comes from either token — it is always looked up here. Symmetric algorithms
/// (`HS256`/`HS384`/`HS512`) must never appear in `allowed_algs`: [`VerifierConfig::new`] filters
/// them out defensively, and `verify()` *also* hard-rejects the whole HMAC family unconditionally
/// regardless of what a caller manages to put in `allowed_algs`. This scheme's private key never
/// leaves the device, so there is no symmetric secret the verifier could ever legitimately share
/// with a signer — belt and braces, not a suggestion.
#[derive(Debug, Clone)]
pub struct VerifierConfig {
    /// Attestation `iss` values this verifier trusts.
    pub trusted_issuers: HashSet<String>,
    /// Algorithms accepted for both the request signature and the attestation. Must be
    /// asymmetric only — see the type-level docs above.
    pub allowed_algs: Vec<Algorithm>,
    /// Clock skew tolerance applied to both the attestation's and the signature's freshness
    /// windows.
    pub max_clock_skew: Duration,
    /// Upper bound on `sig.exp - sig.iat`. Rejects long-lived signatures outright even if `exp`
    /// itself is still in the future — a short-lived signing key policy is only meaningful if
    /// the lifetime is bounded independently of the clock.
    pub max_signature_lifetime: Duration,
    /// The audience this verifier expects requests to be signed for (`sig.aud`). Prevents a
    /// signature captured for one service being replayed against another.
    pub audience: String,
}

impl VerifierConfig {
    /// Builds a config, silently dropping any symmetric algorithm from `allowed_algs`.
    ///
    /// Dropping rather than erroring keeps this ergonomic for the common case (a caller passes
    /// `[Algorithm::ES256]` and never has to think about it) while still making the
    /// "asymmetric only" rule impossible to defeat by misconfiguration — the algorithm-family
    /// check inside `verify()` is the actual enforcement point either way.
    pub fn new(
        trusted_issuers: impl IntoIterator<Item = impl Into<String>>,
        allowed_algs: impl IntoIterator<Item = Algorithm>,
        max_clock_skew: Duration,
        max_signature_lifetime: Duration,
        audience: impl Into<String>,
    ) -> Self {
        let allowed_algs: Vec<Algorithm> = allowed_algs
            .into_iter()
            .filter(|alg| !is_symmetric(*alg))
            .collect();

        Self {
            trusted_issuers: trusted_issuers.into_iter().map(Into::into).collect(),
            allowed_algs,
            max_clock_skew,
            max_signature_lifetime,
            audience: audience.into(),
        }
    }
}

pub(crate) fn is_symmetric(alg: Algorithm) -> bool {
    matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512)
}
