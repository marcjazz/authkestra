use crate::{
    attestation::{
        AttestationConfig, AttestationStatusProvider, EnrolmentChallengeStore, SecondFactorVerifier,
    },
    config::OpConfig,
    store::OpStore,
};
use authkestra_engine::auth::session::SessionStore;
use authkestra_engine::Configured;
use authkestra_engine::Missing;
use authkestra_engine::{Engine, TokenManager};
use std::sync::Arc;

/// OpenID Provider (OP) instance holding required configuration and state.
#[derive(Clone)]
pub struct Op<E = Missing, S = Missing> {
    /// The underlying authentication engine.
    pub engine: E,
    /// OP Configuration.
    pub config: OpConfig,
    /// Store backend for OP.
    pub store: S,
    /// Optional Attestation Configuration.
    pub attestation_config: Option<AttestationConfig>,
    /// Optional Challenge Store for attestation.
    pub challenge_store: Option<Arc<dyn EnrolmentChallengeStore>>,
    /// Optional Second Factor Verifier.
    pub second_factor_verifier: Option<Arc<dyn SecondFactorVerifier>>,
    /// Optional Attestation Status Provider.
    pub status_provider: Option<Arc<dyn AttestationStatusProvider>>,
}

impl Op<Missing, Missing> {
    /// Create a new OP builder enforcing typestates for required dependencies.
    pub fn builder() -> OpBuilder<Missing, Missing> {
        OpBuilder {
            engine: Missing,
            config: None,
            store: Missing,
            attestation_config: None,
            challenge_store: None,
            second_factor_verifier: None,
            status_provider: None,
        }
    }
}

/// A typestate builder for `Op`.
pub struct OpBuilder<E, S> {
    engine: E,
    config: Option<OpConfig>,
    store: S,
    attestation_config: Option<AttestationConfig>,
    challenge_store: Option<Arc<dyn EnrolmentChallengeStore>>,
    second_factor_verifier: Option<Arc<dyn SecondFactorVerifier>>,
    status_provider: Option<Arc<dyn AttestationStatusProvider>>,
}

impl<E, S> OpBuilder<E, S> {
    /// Set the OP configuration.
    pub fn config(mut self, config: OpConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the attestation configuration.
    pub fn attestation_config(mut self, config: AttestationConfig) -> Self {
        self.attestation_config = Some(config);
        self
    }

    /// Set the attestation challenge store.
    pub fn challenge_store(mut self, store: Arc<dyn EnrolmentChallengeStore>) -> Self {
        self.challenge_store = Some(store);
        self
    }

    /// Set the second factor verifier.
    pub fn second_factor_verifier(mut self, verifier: Arc<dyn SecondFactorVerifier>) -> Self {
        self.second_factor_verifier = Some(verifier);
        self
    }

    /// Set the attestation status provider.
    pub fn status_provider(mut self, provider: Arc<dyn AttestationStatusProvider>) -> Self {
        self.status_provider = Some(provider);
        self
    }
}

impl<S> OpBuilder<Missing, S> {
    /// Set the underlying authentication engine, which provides SessionStore and TokenManager.
    pub fn engine<ES, ET>(self, engine: Engine<ES, ET>) -> OpBuilder<Engine<ES, ET>, S> {
        OpBuilder {
            engine,
            config: self.config,
            store: self.store,
            attestation_config: self.attestation_config,
            challenge_store: self.challenge_store,
            second_factor_verifier: self.second_factor_verifier,
            status_provider: self.status_provider,
        }
    }
}

impl<E> OpBuilder<E, Missing> {
    /// Set the OP store, advancing the typestate.
    pub fn store(self, store: Arc<dyn OpStore>) -> OpBuilder<E, Arc<dyn OpStore>> {
        OpBuilder {
            engine: self.engine,
            config: self.config,
            store,
            attestation_config: self.attestation_config,
            challenge_store: self.challenge_store,
            second_factor_verifier: self.second_factor_verifier,
            status_provider: self.status_provider,
        }
    }
}

#[allow(clippy::type_complexity)]
impl
    OpBuilder<
        Engine<Configured<Arc<dyn SessionStore>>, Configured<Arc<TokenManager>>>,
        Arc<dyn OpStore>,
    >
{
    /// Build the `Op` instance. Panics if `config` was not provided.
    pub fn build(
        self,
    ) -> Op<
        Engine<Configured<Arc<dyn SessionStore>>, Configured<Arc<TokenManager>>>,
        Arc<dyn OpStore>,
    > {
        Op {
            engine: self.engine,
            config: self.config.expect("config must be set on OpBuilder"),
            store: self.store,
            attestation_config: self.attestation_config,
            challenge_store: self.challenge_store,
            second_factor_verifier: self.second_factor_verifier,
            status_provider: self.status_provider,
        }
    }
}
