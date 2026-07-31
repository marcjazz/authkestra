//! # Authkestra OP
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
//! Handler logic has landed (see `handlers` for the OIDC endpoint handlers
//! — discovery, JWKS, authorize, token — and `handlers::enrolment` for the
//! device/service attestation enrolment and re-issuance ceremony). See
//! `docs/rfc-003-oidc-provider.md` for the RFC this crate implements.

#![warn(missing_docs)]

/// Errors returned by OP operations.
pub mod error;
pub use error::OpError;

/// Registered OAuth2/OIDC client applications.
pub mod client;
pub use client::{ClientRegistration, ClientStore, GrantType};

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

/// Device Authorization Grant related types.
pub mod device;

/// HTTP handlers for OP endpoints (discovery, jwks, authorize, token).
pub mod handlers;

/// Refresh tokens and rotation logic.
pub mod refresh;

/// Unified OpStore trait.
pub mod store;
pub use store::OpStore;

#[cfg(feature = "sqlx")]
/// Native SQL implementations using sqlx.
pub mod sqlx_store;

/// Provider-level configuration (issuer URL, supported scopes/response
/// types).
pub mod config;
pub use config::OpConfig;
