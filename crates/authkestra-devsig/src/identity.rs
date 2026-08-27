//! The success output of `verify()`.

use serde_json::Value;

/// Identity established by a request that passed every step of the verification algorithm.
///
/// `subject` and `device` come from the attestation; `key_thumbprint` is recomputed by the
/// verifier from the request signature's embedded `jwk` (it necessarily equals the
/// attestation's `cnf.jkt` — that equality *is* the binding check — but it is threaded through
/// separately here to document that this value was derived from the live request, not merely
/// copied out of the attestation).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeviceIdentity {
    /// The attestation's `sub` claim — the authenticated identity.
    pub subject: String,
    /// The attestation's `did` claim — the device identifier.
    pub device: String,
    /// The RFC 7638 SHA-256 thumbprint of the request-signature's embedded `jwk`.
    pub key_thumbprint: String,
    /// The attestation's `att` claim — application attributes. Opaque to this crate; surfaced
    /// as-is to the application.
    pub attributes: Value,
}
