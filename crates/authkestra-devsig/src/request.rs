//! The inbound-request facts `verify()` needs, decoupled from any HTTP framework.
//!
//! This is deliberately not an axum/tower type. The verification core in [`crate::verify`] takes
//! this plain struct so it can be called from a `tower::Layer`, a future authkestra
//! trait-based integration, a CLI test harness, or anything else that can produce these seven
//! fields — the integration surface is free to change without touching the algorithm.

/// The two credential headers plus the request facts needed to check request binding.
pub struct SignedRequest<'a> {
    /// Compact JWS from `X-Signature`.
    pub signature: Option<&'a str>,
    /// Compact JWS from `X-Attestation`.
    pub attestation: Option<&'a str>,
    /// Uppercase HTTP method, e.g. `"POST"`.
    pub method: &'a str,
    /// Request path, percent-encoded, excluding the query string.
    pub path: &'a str,
    /// Raw query string (no leading `?`), if the request has one.
    pub query: Option<&'a str>,
    /// Raw request body bytes, if the request has a body.
    pub body: Option<&'a [u8]>,
}
