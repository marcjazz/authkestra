//! DPoP (RFC 9449) replay tracking for the resource server.
//!
//! This is the [`JwtStrategy`](crate::jwt::JwtStrategy)-side counterpart to
//! `authkestra_engine::token::dpop::verify_dpop_proof`, which verifies one
//! proof in isolation and deliberately does not track replay itself (see
//! that module's doc comment).
//!
//! Deliberately independent from `authkestra-op`'s own DPoP replay guard:
//! an authorization server and a resource server are commonly separate
//! deployments — even separate processes on separate hosts — each needing
//! its own record of which `jti`s it has already seen for proofs presented
//! *to it*. The OP's `/token`-endpoint replay guard has no visibility into,
//! and no bearing on, a fresh proof a client mints when calling a protected
//! resource; that is a second value from the client's key, with its own
//! `jti`, that this crate must independently track.

use crate::jwt::ValidationError;
use authkestra_engine::store::{AtomicInsert, KvStore};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The freshness window a DPoP proof presented to a protected resource is
/// checked against, and, by the same convention
/// `authkestra_engine::token::dpop::verify_dpop_proof`'s own doc comment
/// establishes, the TTL a caller should use when recording its `jti`.
pub const DPOP_PROOF_MAX_AGE_SECS: i64 = 60;

/// Records that a DPoP proof's `jti` has been spent, for proofs presented
/// to this resource server.
///
/// `check_and_record_dpop_jti` **must** be atomic — a `get`-then-`set`
/// implemented as two separate storage calls is a TOCTOU race, and the race
/// is precisely the replay this trait exists to prevent: two concurrent
/// presentations of the same captured proof would both observe "not yet
/// seen".
#[async_trait::async_trait]
pub trait DpopReplayStore: Send + Sync {
    /// Atomically records `jti` as spent until `expires_at`.
    ///
    /// Returns `Ok(true)` if this is its first use (accept the proof) and
    /// `Ok(false)` if it was already recorded (a replay — reject).
    async fn check_and_record_dpop_jti(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, ValidationError>;
}

/// The fail-closed default: refuses every proof.
///
/// A deployment that has not wired replay tracking cannot provide the
/// single-use guarantee RFC 9449 §11.1 calls for, and accepting proofs
/// without it would be strictly worse than not checking DPoP at the
/// resource server at all — clients would believe they had sender-
/// constrained tokens while a captured proof stayed replayable for its
/// whole freshness window. So the default refuses rather than silently
/// degrades — same rationale as `authkestra_op::dpop::NoDpopReplayStore`.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NoDpopReplayStore;

#[async_trait::async_trait]
impl DpopReplayStore for NoDpopReplayStore {
    async fn check_and_record_dpop_jti(
        &self,
        _jti: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<bool, ValidationError> {
        tracing::error!(
            "a DPoP-bound access token was presented along with a DPoP proof, but no \
             DpopReplayStore is wired into this JwtStrategy; refusing it rather than accepting \
             a proof that could be replayed"
        );
        Err(ValidationError::DpopReplayUnavailable(
            "no DpopReplayStore is configured".to_string(),
        ))
    }
}

/// The record a `DpopReplayStore` backend persists for one spent `jti`.
///
/// `#[non_exhaustive]` blocks struct-literal construction from outside this
/// crate, but storage-backend implementations must be able to reconstruct
/// this from their own persisted fields — this is the seam that makes that
/// possible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DpopJtiRecord {
    /// The spent `jti` value. Redundant with the store key it's saved
    /// under, but kept on the record itself so a backend that reconstructs
    /// rows generically (e.g. by scanning) doesn't need the key threaded
    /// separately.
    pub jti: String,
    /// When this record — and the replay protection it provides — expires.
    pub expires_at: DateTime<Utc>,
}

impl DpopJtiRecord {
    /// Creates a new record for a freshly spent `jti`.
    pub fn new(jti: String, expires_at: DateTime<Utc>) -> Self {
        Self { jti, expires_at }
    }
}

/// Blanket impl over any backend that is a `KvStore` with atomic
/// insert-if-absent — every backend `authkestra_engine::store::AtomicInsert`
/// is implemented for (Memory, Redis, Postgres, Sqlite, MySQL) gets
/// `DpopReplayStore` for free, with no DPoP-specific storage code at all.
#[async_trait::async_trait]
impl<S> DpopReplayStore for S
where
    S: KvStore<DpopJtiRecord> + AtomicInsert<DpopJtiRecord>,
{
    async fn check_and_record_dpop_jti(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, ValidationError> {
        tracing::trace!("attempting to record dpop proof jti");
        let ttl = expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        self.insert_if_absent(jti, DpopJtiRecord::new(jti.to_string(), expires_at), ttl)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to record dpop proof jti");
                ValidationError::DpopReplayUnavailable(format!(
                    "failed to record dpop proof jti: {e}"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authkestra_engine::store::memory::MemoryStore;

    #[tokio::test]
    async fn first_use_of_a_jti_is_accepted() {
        let store = MemoryStore::<DpopJtiRecord>::new();
        let expires_at = Utc::now() + chrono::Duration::seconds(60);

        let accepted = store
            .check_and_record_dpop_jti("jti-1", expires_at)
            .await
            .unwrap();
        assert!(accepted);
    }

    #[tokio::test]
    async fn a_replayed_jti_is_rejected() {
        let store = MemoryStore::<DpopJtiRecord>::new();
        let expires_at = Utc::now() + chrono::Duration::seconds(60);

        assert!(store
            .check_and_record_dpop_jti("jti-1", expires_at)
            .await
            .unwrap());

        let replayed = store
            .check_and_record_dpop_jti("jti-1", expires_at)
            .await
            .unwrap();
        assert!(
            !replayed,
            "a second presentation of the same jti must be rejected"
        );
    }

    #[tokio::test]
    async fn distinct_jtis_are_independent() {
        let store = MemoryStore::<DpopJtiRecord>::new();
        let expires_at = Utc::now() + chrono::Duration::seconds(60);

        assert!(store
            .check_and_record_dpop_jti("jti-1", expires_at)
            .await
            .unwrap());
        assert!(store
            .check_and_record_dpop_jti("jti-2", expires_at)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn no_dpop_replay_store_fails_closed() {
        let err = NoDpopReplayStore
            .check_and_record_dpop_jti("jti-1", Utc::now())
            .await
            .expect_err("the fail-closed default must refuse every proof");
        assert!(matches!(err, ValidationError::DpopReplayUnavailable(_)));
    }
}
