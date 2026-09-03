use thiserror::Error;

/// Errors that can occur during OpenID Provider operations.
#[derive(Debug, Error)]
pub enum OpError {
    /// The requested client_id is not registered.
    #[error("unknown client: {0}")]
    UnknownClient(String),

    /// The provided redirect_uri does not match a registered URI for this
    /// client — exactly, or, for a loopback IP URI, on every component but
    /// the port (RFC 8252 §7.3; see
    /// [`crate::client::ClientRegistration::allows_redirect_uri`]). Always
    /// treat this as a hard failure — never fall back to a "closest match"
    /// or prefix comparison.
    #[error("redirect_uri does not match a registered URI for this client")]
    RedirectUriMismatch,

    /// The authorization code was not found, already used, or expired.
    #[error("invalid or expired authorization code")]
    InvalidCode,

    /// PKCE verification failed.
    #[error("PKCE verification failed")]
    PkceMismatch,

    /// The client_secret did not match the stored hash.
    #[error("invalid client credentials")]
    InvalidClientCredentials,

    /// The requested grant_type is not enabled for this client.
    #[error("grant_type not permitted for this client")]
    GrantTypeNotPermitted,

    /// The client presented a credential of a different kind than the one it
    /// is registered for — a `client_secret` from a `private_key_jwt` client,
    /// or a `client_assertion` from a `client_secret_*` client. Rejected
    /// rather than accepted-because-it-verifies: a client that can
    /// authenticate by either means is only as strong as the weaker of the
    /// two (see `client::TokenEndpointAuthMethod`).
    #[error("client authentication method not permitted for this client")]
    AuthMethodNotPermitted,

    /// The presented `client_assertion` is malformed, was not signed by a key
    /// in the client's registered JWK Set, or carries claims that do not
    /// satisfy RFC 7523 §3.
    ///
    /// Deliberately one opaque variant covering all of those: the caller of a
    /// failed client authentication learns only `invalid_client` either way,
    /// and distinguishing "bad signature" from "wrong `aud`" here only
    /// creates a way for that distinction to leak into a response.
    #[error("invalid client assertion")]
    InvalidClientAssertion,

    /// The presented `client_assertion` carries a `jti` that has already been
    /// spent (RFC 7523 §3 point 7). A captured assertion is a bearer
    /// credential until it expires; single-use `jti` is what stops it from
    /// being one.
    #[error("client assertion replayed")]
    ClientAssertionReplayed,

    /// The deployment's `OpStore` provides no `jti` replay tracking, so
    /// `private_key_jwt` cannot be honoured safely. Fails closed on purpose —
    /// see `store::OpStore::record_client_assertion_jti`.
    #[error("client assertion replay protection is not configured")]
    ReplayProtectionUnavailable,

    /// The presented DPoP proof carries a `jti` that has already been spent
    /// (RFC 9449 §11.1). A captured proof is otherwise reusable for as long
    /// as it stays within its freshness window; single-use `jti` is what
    /// stops it from being replayed within that window.
    #[error("dpop proof replayed")]
    DpopProofReplayed,

    /// The deployment's `OpStore` provides no DPoP `jti` replay tracking, so
    /// a presented DPoP proof cannot be honoured safely. Fails closed on
    /// purpose — see `store::OpStore::check_and_record_dpop_jti`.
    #[error("dpop proof replay protection is not configured")]
    DpopReplayProtectionUnavailable,

    /// Underlying storage error, opaque to the caller by design — storage
    /// backends should not leak implementation details (e.g. SQL errors)
    /// into OAuth error responses.
    #[error("storage error")]
    Storage,

    /// Token issuance failed at the `authkestra_engine::TokenManager` layer.
    #[error("token issuance failed: {0}")]
    TokenIssuance(String),

    /// The submitted enrolment/re-issuance challenge was not found, already
    /// used, or expired. Challenges are single-use by design (spec §5.6
    /// steps 3-5); callers should not distinguish "unknown" from "expired"
    /// from "already used" in the response, to avoid leaking timing or
    /// existence information.
    #[error("invalid or expired enrolment challenge")]
    InvalidChallenge,

    /// The submitted JWK is malformed, carries a private or symmetric-secret
    /// component, or uses a key type this method does not accept.
    #[error("invalid public key: {0}")]
    BadJwk(String),

    /// The signature presented at enrolment/re-issuance completion did not
    /// verify against the JWK submitted alongside the challenge —
    /// proof-of-possession failed.
    #[error("challenge signature verification failed")]
    ChallengeSignatureInvalid,

    /// A disallowed algorithm was offered — `none`, or a symmetric
    /// algorithm, where only asymmetric algorithms are ever valid for this
    /// method (spec §5.7.1).
    #[error("disallowed algorithm: {0}")]
    BadAlg(String),

    /// The attestation presented to begin re-issuance failed to validate
    /// (bad signature, expired, or missing the claims this ceremony
    /// requires).
    #[error("presented attestation is invalid or expired")]
    AttestationInvalid,

    /// The JWK submitted for re-issuance does not thumbprint-match the
    /// `cnf.jkt` bound in the presented attestation. This is the same
    /// binding check the request-signature verifier performs on every
    /// ordinary request (spec §4 step 4), applied here so re-issuance
    /// cannot be used to silently rebind an attestation to a different key
    /// without repeating full enrolment.
    #[error("submitted key does not match the attestation's bound key")]
    KeyNotBound,

    /// The application-supplied `SecondFactorVerifier` rejected the
    /// enrolment request.
    #[error("second-factor verification failed")]
    SecondFactorFailed,

    /// The application's `AttestationStatusProvider` reports this principal
    /// as no longer active — re-issuance is refused rather than silently
    /// extending a revoked principal's access.
    #[error("principal is revoked or inactive")]
    PrincipalRevoked,
}

impl From<authkestra_engine::store::StoreError> for OpError {
    fn from(err: authkestra_engine::store::StoreError) -> Self {
        use authkestra_engine::store::traits::{
            CLIENT_ASSERTION_REPLAY_PROTECTION_UNAVAILABLE, DPOP_REPLAY_PROTECTION_UNAVAILABLE,
        };
        use authkestra_engine::store::StoreError;

        // `NoClientAssertionStore`/`NoDpopReplayStore` fail with these exact
        // `Internal` payloads specifically so this impl can recover the
        // distinct variant below, rather than every missing-replay-store
        // misconfiguration collapsing into the same opaque `OpError::Storage`
        // a genuine backend failure would produce.
        match &err {
            StoreError::Internal(msg) if msg == CLIENT_ASSERTION_REPLAY_PROTECTION_UNAVAILABLE => {
                return OpError::ReplayProtectionUnavailable;
            }
            StoreError::Internal(msg) if msg == DPOP_REPLAY_PROTECTION_UNAVAILABLE => {
                return OpError::DpopReplayProtectionUnavailable;
            }
            _ => {}
        }
        tracing::error!("StoreError: {}", err);
        OpError::Storage
    }
}

#[cfg(test)]
mod tests {
    use super::OpError;
    use authkestra_engine::store::StoreError;

    /// `NoClientAssertionStore`/`NoDpopReplayStore` (in `authkestra-engine`)
    /// and this `From` impl (in `authkestra-op`) agree on these two exact
    /// strings across the crate boundary via shared `pub const`s — this
    /// pins that the mapping actually recovers the distinct variants,
    /// rather than silently falling through to the generic
    /// `OpError::Storage` every other `StoreError` produces.
    #[test]
    fn a_missing_client_assertion_store_is_distinguishable_from_a_generic_storage_error() {
        let err: OpError = StoreError::Internal(
            authkestra_engine::store::traits::CLIENT_ASSERTION_REPLAY_PROTECTION_UNAVAILABLE
                .to_string(),
        )
        .into();
        assert!(matches!(err, OpError::ReplayProtectionUnavailable));
    }

    #[test]
    fn a_missing_dpop_replay_store_is_distinguishable_from_a_generic_storage_error() {
        let err: OpError = StoreError::Internal(
            authkestra_engine::store::traits::DPOP_REPLAY_PROTECTION_UNAVAILABLE.to_string(),
        )
        .into();
        assert!(matches!(err, OpError::DpopReplayProtectionUnavailable));
    }

    #[test]
    fn an_unrelated_storage_error_stays_generic() {
        let err: OpError = StoreError::Internal("some other backend failure".to_string()).into();
        assert!(matches!(err, OpError::Storage));
    }
}
