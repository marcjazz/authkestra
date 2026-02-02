//! Authkestra is a modular authentication framework for Rust.
//!
//! This crate serves as a facade, re-exporting functionality from other `authkestra-*` crates
//! based on enabled features.

pub use authkestra_core as core;

#[cfg(feature = "flow")]
pub use authkestra_flow as flow;

#[cfg(feature = "session")]
pub use authkestra_session as session;

#[cfg(feature = "token")]
pub use authkestra_token as token;

#[cfg(feature = "oidc")]
pub use authkestra_oidc as oidc;

#[cfg(feature = "axum")]
pub use authkestra_axum as axum;

#[cfg(feature = "actix")]
pub use authkestra_actix as actix;

/// Authentication providers.
pub mod providers {
    #[cfg(feature = "github")]
    pub use authkestra_providers_github as github;

    #[cfg(feature = "google")]
    pub use authkestra_providers_google as google;

    #[cfg(feature = "discord")]
    pub use authkestra_providers_discord as discord;
}
