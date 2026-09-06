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

#[cfg(feature = "axum")]
pub use authkestra_axum as axum;

#[cfg(feature = "actix")]
pub use authkestra_actix as actix;

/// The OpenID Provider server: `OpConfig`, `OpStore` and the handlers the
/// adapters' `op` routes are built from.
///
/// Re-exported alongside the adapters' `op` feature because those routes are
/// configured with types from this crate — forwarding the feature without it
/// would leave the endpoints reachable but unconfigurable (#325).
#[cfg(feature = "op")]
pub use authkestra_op as op;

/// Device and service signatures: `DeviceIdentity`, `SignedRequest` and the
/// verification entry points the adapters' `devsig` layers wrap.
#[cfg(feature = "devsig")]
pub use authkestra_devsig as devsig;

/// Authentication providers.
pub mod providers {
    #[cfg(feature = "github")]
    pub use authkestra_providers::github;

    #[cfg(feature = "google")]
    pub use authkestra_providers::google;

    #[cfg(feature = "discord")]
    pub use authkestra_providers::discord;
}
