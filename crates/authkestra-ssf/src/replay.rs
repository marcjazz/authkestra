//! Replay protection for SETs, keyed by `(iss, jti)`.
//!
//! RFC 8417 §2.2 says `jti` "MUST be unique within a particular event feed and MAY be used by
//! clients to track whether a particular SET has already been received" — hence the composite
//! key: two transmitters may legitimately mint the same `jti`, and treating them as one would
//! drop a real event.
//!
//! Note what this is *not* for. RFC 8935 §2 requires a receiver to answer a retransmitted SET
//! exactly as it would answer a first transmission, so detecting a replay must not turn into an
//! error response — see [`crate::PushReceiver::receive`]. The guard exists so the *handlers* run
//! once, not so the transmitter gets told off.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

/// Records which SETs have already been ingested.
///
/// Returns `true` when the SET is new and processing should continue, `false` when it has
/// already been seen. There is no error case on purpose: an implementation whose backing store
/// is unreachable must decide locally between failing closed (`false`, at the cost of dropping
/// events during an outage) and failing open (`true`, at the cost of duplicate handler
/// invocations) — and that trade-off depends on whether the deployment's handlers are
/// idempotent, which this crate cannot know. Whichever it picks, it should log the outage.
#[async_trait]
pub trait SetReplayGuard: Send + Sync + 'static {
    /// Atomically records `(iss, jti)` if absent, and reports whether it was newly recorded.
    async fn check_and_record(&self, jti: &str, iss: &str) -> bool;
}

/// A `HashMap`-backed [`SetReplayGuard`] with a fixed entry TTL.
///
/// Single-process only: two receiver instances each keep their own map, so a SET replayed to a
/// *different* instance is seen as new. Deployments running more than one receiver want a shared
/// store (e.g. Redis `SET key val NX PX ttl`) behind the same trait.
///
/// Entries are swept lazily on each call rather than by a background task, so an idle receiver
/// holds its last window's worth of `jti`s until the next SET arrives. That is a deliberate
/// trade: a timer task would need a runtime handle and a shutdown story for what is, at most, a
/// few kilobytes of strings.
pub struct InMemorySetReplayGuard {
    ttl: Duration,
    seen: Mutex<HashMap<(String, String), Instant>>,
}

impl InMemorySetReplayGuard {
    /// Creates a guard that remembers each `(iss, jti)` for `ttl`.
    ///
    /// `ttl` should comfortably exceed the transmitter's retransmission window (RFC 8935 §4
    /// leaves retry timing to the transmitter): once an entry expires, a retransmission is
    /// indistinguishable from a new event and handlers run again.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// How many entries are currently retained, after sweeping expired ones.
    pub fn len(&self) -> usize {
        let mut seen = self.seen.lock().expect("replay guard mutex poisoned");
        let now = Instant::now();
        seen.retain(|_, recorded_at| now.duration_since(*recorded_at) < self.ttl);
        seen.len()
    }

    /// Whether nothing is currently retained.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl SetReplayGuard for InMemorySetReplayGuard {
    async fn check_and_record(&self, jti: &str, iss: &str) -> bool {
        let now = Instant::now();
        let mut seen = self.seen.lock().expect("replay guard mutex poisoned");

        seen.retain(|_, recorded_at| now.duration_since(*recorded_at) < self.ttl);

        let key = (iss.to_string(), jti.to_string());
        if seen.contains_key(&key) {
            tracing::warn!(
                target: "authkestra_ssf",
                jti = %jti,
                iss = %iss,
                "SET jti already recorded; treating as a replay"
            );
            return false;
        }
        seen.insert(key, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_then_detects_a_replay() {
        let guard = InMemorySetReplayGuard::new(Duration::from_secs(60));
        assert!(guard.check_and_record("jti-1", "https://idp/").await);
        assert!(!guard.check_and_record("jti-1", "https://idp/").await);
        assert_eq!(guard.len(), 1);
        assert!(!guard.is_empty());
    }

    #[tokio::test]
    async fn scopes_jti_to_the_issuer() {
        let guard = InMemorySetReplayGuard::new(Duration::from_secs(60));
        assert!(guard.check_and_record("jti-1", "https://a/").await);
        assert!(
            guard.check_and_record("jti-1", "https://b/").await,
            "the same jti from a different feed is a different SET (RFC 8417 §2.2)"
        );
        assert_eq!(guard.len(), 2);
    }

    #[tokio::test]
    async fn expires_entries_after_the_ttl() {
        let guard = InMemorySetReplayGuard::new(Duration::from_millis(20));
        assert!(guard.check_and_record("jti-1", "https://idp/").await);
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(guard.is_empty(), "the entry should have been swept");
        assert!(
            guard.check_and_record("jti-1", "https://idp/").await,
            "after the TTL, the same jti is accepted again"
        );
    }
}
