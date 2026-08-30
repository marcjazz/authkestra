//! DPoP (RFC 9449) replay tracking — the OP-side counterpart to
//! `authkestra_engine::token::dpop::verify_dpop_proof`, which verifies one
//! proof in isolation and deliberately does not track replay itself (see
//! that module's doc comment).
//!
//! A DPoP proof's `jti` is client-generated, never server-issued — unlike
//! an authorization code or enrolment challenge, there is nothing for this
//! server to have stored ahead of time. The check is "was this `jti`
//! already claimed", which is exactly the shape
//! `authkestra_engine::store::AtomicInsert` provides, not
//! [`authkestra_engine::store::AtomicConsume`] (the primitive
//! [`crate::attestation::EnrolmentChallengeStore`] and
//! [`crate::code::AuthorizationCodeStore`] are built on, for server-issued
//! single-use values).

use crate::error::OpError;
use async_trait::async_trait;
use authkestra_engine::store::{AtomicInsert, KvStore};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The freshness window a DPoP proof is checked against, and — by the same
/// convention `verify_dpop_proof`'s own doc comment establishes — the TTL a
/// caller should use when recording its `jti`: a proof can never be
/// usefully replayed after its own freshness window has elapsed, since it
/// would independently fail that check first.
///
/// A constant rather than an `OpConfig` field on purpose: `OpConfig` is not
/// `#[non_exhaustive]` and is constructed with struct literals throughout
/// this workspace, so growing it is a breaking change this feature does not
/// need to make — same reasoning
/// `client_assertion::MAX_CLIENT_ASSERTION_LIFETIME_SECS` already
/// established for an equivalent constraint.
pub const DPOP_PROOF_MAX_AGE_SECS: i64 = 60;

/// Records that a DPoP proof's `jti` has been spent.
///
/// `check_and_record_dpop_jti` **must** be atomic — a `get`-then-`set`
/// implemented as two separate storage calls is a TOCTOU race, and the race
/// is precisely the replay this trait exists to prevent: two concurrent
/// presentations of the same captured proof would both observe "not yet
/// seen". Same requirement, and the same reasoning, as
/// `ClientAssertionStore::record_jti`.
#[async_trait]
pub trait DpopReplayStore: Send + Sync {
    /// Atomically records `jti` as spent until `expires_at`.
    ///
    /// Returns `Ok(true)` if this is its first use (accept the proof) and
    /// `Ok(false)` if it was already recorded (a replay — reject).
    async fn check_and_record_dpop_jti(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, OpError>;
}

/// The fail-closed default: refuses every proof.
///
/// A deployment that has not wired replay tracking cannot provide the
/// single-use guarantee RFC 9449 §11.1 calls for, and accepting proofs
/// without it would be strictly worse than not supporting DPoP at all —
/// clients would believe they had sender-constrained tokens while a
/// captured proof stayed replayable for its whole freshness window. So the
/// default refuses rather than silently degrades — same rationale as
/// `NoClientAssertionStore`.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NoDpopReplayStore;

#[async_trait]
impl DpopReplayStore for NoDpopReplayStore {
    async fn check_and_record_dpop_jti(
        &self,
        _jti: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<bool, OpError> {
        tracing::error!(
            "a DPoP proof was presented but no DpopReplayStore is wired; refusing it rather \
             than accepting a proof that could be replayed"
        );
        Err(OpError::DpopReplayProtectionUnavailable)
    }
}

/// The record a `DpopReplayStore` backend persists for one spent `jti`.
///
/// `#[non_exhaustive]` blocks struct-literal construction from outside this
/// crate, but storage-backend implementations must be able to reconstruct
/// this from their own persisted fields — this is the seam that makes that
/// possible, same shape as `AuthorizationCode::new`/`RefreshToken::new`.
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
/// insert-if-absent — the first real consumer of
/// `authkestra_engine::store::AtomicInsert` in this crate. Unlike
/// `ClientAssertionStore`'s hand-rolled per-backend implementations
/// (written before `AtomicInsert` existed), every backend Phase A already
/// implemented it for (Memory, Redis, Postgres, Sqlite, MySQL) gets
/// `DpopReplayStore` for free, with no DPoP-specific storage code at all.
#[async_trait]
impl<S> DpopReplayStore for S
where
    S: KvStore<DpopJtiRecord> + AtomicInsert<DpopJtiRecord>,
{
    async fn check_and_record_dpop_jti(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, OpError> {
        tracing::trace!("attempting to record dpop proof jti");
        let ttl = expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0));

        self.insert_if_absent(jti, DpopJtiRecord::new(jti.to_string(), expires_at), ttl)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to record dpop proof jti");
                OpError::Storage
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
        assert!(matches!(err, OpError::DpopReplayProtectionUnavailable));
    }
}
