//! Authkestra is a modular authentication framework for Rust.
//!
//! This crate serves as a facade, re-exporting functionality from other `authkestra-*` crates
//! based on enabled features.

pub use authkestra_engine as core;

/// Type alias for the Engine to support the Authkestra::builder() pattern.
pub type Authkestra<S = authkestra_engine::Missing, T = authkestra_engine::Missing> =
    authkestra_engine::Engine<S, T>;

pub use authkestra_engine as flow;

#[cfg(feature = "session")]
pub use authkestra_engine::store;

#[cfg(feature = "token")]
pub use authkestra_engine as token;

#[cfg(feature = "oidc")]
pub use authkestra_oidc as oidc;

/// Cedar policy engine — **proof of concept**, see
/// [authkestra#21](https://github.com/marcjazz/authkestra/issues/21) and
/// `docs/rfc-005-policy-engine.md`.
///
/// Re-exported so it can be tried behind one feature flag, but it is not wired into any guard,
/// extractor, or middleware yet: enabling `policy` adds an authorization engine you call
/// yourself, it does not change how any existing route is protected.
#[cfg(feature = "policy")]
pub use authkestra_policy as policy;

#[cfg(feature = "axum")]
pub use authkestra_axum as axum;

#[cfg(feature = "actix")]
pub use authkestra_actix as actix;

/// Authentication providers.
pub mod providers {
    #[cfg(feature = "github")]
    pub use authkestra_providers::github;

    #[cfg(feature = "google")]
    pub use authkestra_providers::google;

    #[cfg(feature = "discord")]
    pub use authkestra_providers::discord;
}
