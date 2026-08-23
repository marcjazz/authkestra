//! RFC 8705 §3 certificate-bound access tokens.
//!
//! This module computes the `cnf.x5t#S256` confirmation value — the
//! base64url (no padding) SHA-256 thumbprint of a client's DER-encoded X.509
//! certificate — and nothing more. It does not parse X.509, does not
//! terminate TLS, and does not validate a certificate chain: extracting the
//! *actual* peer certificate presented on a live mTLS connection is a
//! framework/deployment concern, deliberately left outside this
//! framework-agnostic crate (see [`ClientCertificateDer`]'s doc comment for
//! where that hand-off happens today).
//!
//! Consumed by `authkestra-op::handlers::token::handle_client_credentials`
//! (to stamp `cnf.x5t#S256` at issuance) and by
//! `authkestra-resource::jwt::JwtStrategy` (to verify a presented
//! certificate against it) — see issue #224.

use base64::Engine;
use sha2::{Digest, Sha256};

/// The DER-encoded bytes of a client certificate presented on the current
/// connection.
///
/// Neither `authkestra-op` nor `authkestra-resource` terminates TLS itself,
/// so nothing in this crate family populates a `ClientCertificateDer`
/// automatically. A host application — or the mTLS-terminating layer it
/// runs in front of/alongside its service (a reverse proxy, an
/// `axum-server`/actix-web rustls acceptor configured to require and expose
/// client certificates, etc.) — is responsible for extracting the peer
/// certificate and handing its DER bytes to this crate:
///
/// - On the OP side, `authkestra-axum`'s `axum_token_handler` reads one back
///   out of an `axum::Extension<ClientCertificateDer>` (so a host inserts it
///   as a request extension via its own middleware/acceptor), and
///   `authkestra-actix`'s `actix_token_handler` reads one out of the actix
///   request's own extension map the same way. Both then forward the DER
///   bytes into
///   [`handle_token_with_client_cert`](../../../authkestra_op/handlers/token/fn.handle_token_with_client_cert.html).
/// - On the resource-server side, `JwtStrategy::authenticate` looks one up
///   in the `http::request::Parts` extension map it is handed, when
///   `ValidationConfig::require_cert_binding` is set.
///
/// If nothing ever inserts one, callers simply see `None` throughout, and
/// `client_credentials` tokens are issued as plain (unbound) bearer tokens,
/// same as before this existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificateDer(pub Vec<u8>);

/// Computes the RFC 8705 §3 `x5t#S256` confirmation value: base64url
/// (no padding) of the SHA-256 digest of the DER-encoded certificate.
pub fn x5t_s256_thumbprint(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Constant-time comparison of two `x5t#S256` thumbprints (or any two
/// strings) — a short, dependency-free byte-XOR loop rather than pulling in
/// `subtle` for a single fixed-length string comparison. Mirrors
/// `authkestra_op::attestation::constant_time_eq`, used for the analogous
/// `cnf.jkt` device-attestation check.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-checked against an independent implementation:
    /// `printf 'hello' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='`.
    #[test]
    fn x5t_s256_matches_known_answer_vector() {
        assert_eq!(
            x5t_s256_thumbprint(b"hello"),
            "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
        );
    }

    #[test]
    fn x5t_s256_is_deterministic() {
        assert_eq!(
            x5t_s256_thumbprint(b"cert-bytes"),
            x5t_s256_thumbprint(b"cert-bytes")
        );
    }

    #[test]
    fn x5t_s256_differs_for_different_certs() {
        assert_ne!(
            x5t_s256_thumbprint(b"cert-a"),
            x5t_s256_thumbprint(b"cert-b")
        );
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
