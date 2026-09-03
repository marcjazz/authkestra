//! The orchestrator: runs the full verification algorithm end to end, in the mandated order —
//! cheap checks first, the binding check before anything is allowed to trust the embedded key,
//! replay recorded last and only once everything else has already succeeded.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::attestation;
use crate::config::VerifierConfig;
use crate::error::VerifyError;
use crate::identity::DeviceIdentity;
use crate::jwks::IssuerJwks;
use crate::replay::ReplayStore;
use crate::request::SignedRequest;
use crate::signature;

/// Verifies a device-bound signed request against the configured trust policy.
///
/// `request.signature` and `request.attestation` carry the two credentials (see
/// [`SignedRequest`]); this function is deliberately framework-agnostic so it can be called from
/// a `tower::Layer` (see the optional `axum` feature), a future authkestra trait-based
/// integration, or a plain test harness — the algorithm itself does not care which.
///
/// Order, and why it is load-bearing:
///
/// 1. **Presence** — both credentials must be present. An attestation alone is a bearer token
///    (it is public, travels in every request, and is likely logged); rejecting this case is
///    what keeps the attestation from becoming exactly the weaker-than-normal scheme this design
///    exists to avoid.
/// 2. **Parse + `alg` check** — for both credentials, cheap, before any cryptographic work.
/// 3. **Attestation trust** — issuer, `kid`, signature, expiry, device status.
/// 4. **The binding** — recompute the embedded `jwk`'s RFC 7638 thumbprint and compare it,
///    constant-time, to the attestation's `cnf.jkt`. **This is the step that cannot be inferred
///    from the other two.** An attacker holding a victim's attestation (public, not secret) and
///    their own genuinely-held keypair passes steps 3 and 5 independently and completely; only
///    this comparison detects that the two credentials describe different keys. Skipping,
///    reordering, or short-circuiting it is a total authentication bypass.
/// 5. **Request-signature verification** against that now-bound `jwk`.
/// 6. **Freshness** — skew window, maximum signature lifetime.
/// 7. **Request binding** — method, path, audience, query hash, body hash.
/// 8. **Replay** — recorded last, and fails closed on any store error, not just "already
///    present". A replay store that cannot be reached must reject exactly as if the `jti` had
///    already been seen; falling back to "allow" would silently disable replay protection during
///    an outage, which is worse than rejecting traffic.
pub async fn verify(
    request: &SignedRequest<'_>,
    config: &VerifierConfig,
    jwks: &IssuerJwks,
    replay_store: &dyn ReplayStore,
) -> Result<DeviceIdentity, VerifyError> {
    // --- Step 1: PRESENCE ---
    let (sig_token, att_token) = match (request.signature, request.attestation) {
        (Some(s), Some(a)) => (s, a),
        _ => {
            tracing::debug!(target: "authkestra_devsig", "rejecting request: missing_credential");
            return Err(VerifyError::MissingCredential);
        }
    };

    let now = current_unix_time();

    // --- Step 2: PARSE (both credentials, cheap, before any crypto) ---
    let parsed_att = attestation::parse(att_token, &config.allowed_algs)?;
    let parsed_sig = signature::parse(sig_token, &config.allowed_algs)?;

    // --- Step 3: ATTESTATION TRUST ---
    let att = attestation::verify_trust(&parsed_att, config, jwks, now).await?;

    // --- Steps 4-7: THE BINDING, REQUEST SIGNATURE, FRESHNESS, REQUEST BINDING ---
    let sig = signature::verify_bound_and_signed(&parsed_sig, request, config, &att.jkt, now)?;

    // --- Step 8: REPLAY — fails closed: a store error rejects exactly like a genuine replay,
    // never falls back to "allow". ---
    let ttl = Duration::from_secs((sig.exp - now).max(0) as u64);
    match replay_store.put_if_absent(&sig.jti, ttl).await {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(target: "authkestra_devsig", jti = %sig.jti, "rejecting request: jti already seen (replay_detected)");
            return Err(VerifyError::ReplayDetected);
        }
        Err(store_err) => {
            tracing::error!(target: "authkestra_devsig", error = %store_err, "rejecting request: replay store unreachable, failing closed");
            return Err(VerifyError::ReplayDetected);
        }
    }

    tracing::debug!(
        target: "authkestra_devsig",
        subject = %att.sub,
        device = %att.did,
        "device-signature request accepted"
    );

    Ok(DeviceIdentity::new(
        att.sub,
        att.did,
        sig.jwk_thumbprint,
        att.att,
    ))
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970-01-01")
        .as_secs() as i64
}
