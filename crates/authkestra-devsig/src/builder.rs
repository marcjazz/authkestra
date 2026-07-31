use crate::{config::VerifierConfig, jwks::IssuerJwks, replay::ReplayStore};
use std::sync::Arc;
/// Marker type for a missing dependency in the builder.
pub struct Missing;

/// Device-bound signature verifier instance holding required configuration and state.
pub struct DevSig<R = Missing> {
    /// Verifier Configuration.
    pub config: VerifierConfig,
    /// JWKS of the issuer.
    pub jwks: IssuerJwks,
    /// Replay store backend.
    pub replay_store: R,
}

impl DevSig<Missing> {
    /// Create a new DevSig builder enforcing typestates for required dependencies.
    pub fn builder() -> DevSigBuilder<Missing> {
        DevSigBuilder {
            config: None,
            jwks: None,
            replay_store: Missing,
        }
    }
}

/// A typestate builder for `DevSig`.
pub struct DevSigBuilder<R> {
    config: Option<VerifierConfig>,
    jwks: Option<IssuerJwks>,
    replay_store: R,
}

impl<R> DevSigBuilder<R> {
    /// Set the verifier configuration.
    pub fn config(mut self, config: VerifierConfig) -> Self {
        self.config = Some(config);
        self
    }
    
    /// Set the issuer JWKS.
    pub fn jwks(mut self, jwks: IssuerJwks) -> Self {
        self.jwks = Some(jwks);
        self
    }
}

impl DevSigBuilder<Missing> {
    /// Set the replay store, advancing the typestate.
    pub fn replay_store(self, replay_store: Arc<dyn ReplayStore>) -> DevSigBuilder<Arc<dyn ReplayStore>> {
        DevSigBuilder {
            config: self.config,
            jwks: self.jwks,
            replay_store,
        }
    }
}

impl DevSigBuilder<Arc<dyn ReplayStore>> {
    /// Build the `DevSig` instance. Panics if `config` or `jwks` was not provided.
    pub fn build(self) -> DevSig<Arc<dyn ReplayStore>> {
        DevSig {
            config: self.config.expect("config must be set on DevSigBuilder"),
            jwks: self.jwks.expect("jwks must be set on DevSigBuilder"),
            replay_store: self.replay_store,
        }
    }
}
