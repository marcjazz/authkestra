//! # Engine OP
//!
//! `authkestra-op` implements the OpenID Provider (OP) side of OIDC: issuing
//! tokens and running the authorization code grant, as opposed to
//! `authkestra-oidc`, which consumes an *external* OP as a relying party.
//!
//! This crate is intentionally handler-logic-only — it has no dependency on
//! any web framework. `authkestra-axum` and `authkestra-actix` (behind an
//! `op` feature flag) wrap these types into framework-native routes.
//!
//! ## Status
//! This crate implements the foundational authorization and attestation flows.

#![warn(missing_docs)]

/// Errors returned by OP operations.
pub mod error;
pub use error::OpError;

/// Registered OAuth2/OIDC client applications.
pub mod client;
pub use client::{ClientRegistration, ClientStore, GrantType, TokenEndpointAuthMethod};

/// Asymmetric client authentication (`private_key_jwt`, RFC 7523 §2.2):
/// assertion verification and the replay tracking it depends on.
pub mod client_assertion;
pub use client_assertion::{
    ClientAssertionStore, MemoryClientAssertionStore, NoClientAssertionStore,
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
};

/// Authorization codes issued during the `/authorize` step and consumed at
/// `/token`.
pub mod code;
pub use code::{AuthorizationCode, AuthorizationCodeStore};

/// Device/service attestation issuance: the enrolment/re-issuance ceremony
/// and `cnf.jkt`-bound attestation minting for the device-bound-signature
/// authentication method. See `handlers::enrolment` for the request/
/// response handlers built on top of these types.
pub mod attestation;
pub use attestation::{
    AttestationConfig, AttestationStatusProvider, EnrolmentChallenge, EnrolmentChallengeStore,
    PrincipalType, SecondFactorProof, SecondFactorVerifier,
};

/// Strict Ed25519 gating in front of `jsonwebtoken`'s non-strict EdDSA
/// backend (authkestra#256). Deliberately `pub(crate)`: it is an internal
/// hardening detail of `attestation` and `client_assertion`, not an API this
/// crate wants to be held to — the day `jsonwebtoken` verifies strictly on
/// its own, this module should be deletable without a breaking release.
pub(crate) mod strict_jws;

/// Device Authorization Grant related types.
pub mod device;

/// HTTP handlers for OP endpoints (discovery, jwks, authorize, token).
pub mod handlers;

/// Refresh tokens and rotation logic.
pub mod refresh;

/// Unified OpStore trait.
pub mod store;
pub use store::OpStore;

#[cfg(feature = "redis")]
/// Redis-backed implementations.
pub mod redis_store;

#[cfg(feature = "sqlx")]
/// Native SQL implementations using sqlx.
pub mod sqlx_store;

/// Provider-level configuration (issuer URL, supported scopes/response
/// types).
pub mod config;
pub use config::OpConfig;

// `handlers` contains the implementation of the OP endpoints.
/// Unified OpBuilder pattern
pub mod builder;
pub use builder::{Op, OpBuilder};
