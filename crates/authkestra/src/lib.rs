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

/// Shared Signals Framework (RFC 8417 / RFC 8935) and CAEP event ingestion.
///
/// Only the receiving half — validating SETs and decoding CAEP events. Reacting to an event
/// (session revocation, middleware enforcement) is not implemented yet; see the crate docs and
/// [authkestra#25](https://github.com/marcjazz/authkestra/issues/25).
#[cfg(feature = "ssf")]
pub use authkestra_ssf as ssf;

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
