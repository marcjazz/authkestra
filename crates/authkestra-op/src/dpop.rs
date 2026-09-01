/// RFC 9449 §4.2's recommended freshness window for a DPoP proof's `iat` claim.
pub const DPOP_PROOF_MAX_AGE_SECS: i64 = 60;
pub use authkestra_engine::store::traits::{DpopJtiRecord, DpopReplayStore, NoDpopReplayStore};
