use crate::{config::OpConfig, store::OpStore};
use authkestra_engine::Missing;
use std::sync::Arc;

/// OpenID Provider (OP) instance holding required configuration and state.
#[derive(Clone)]
pub struct Op<S = Missing> {
    /// OP Configuration.
    pub config: OpConfig,
    /// Store backend for OP.
    pub store: S,
}

impl Op<Missing> {
    /// Create a new OP builder enforcing typestates for required dependencies.
    pub fn builder() -> OpBuilder<Missing> {
        OpBuilder {
            config: None,
            store: Missing,
        }
    }
}

/// A typestate builder for `Op`.
pub struct OpBuilder<S> {
    config: Option<OpConfig>,
    store: S,
}

impl<S> OpBuilder<S> {
    /// Set the OP configuration.
    pub fn config(mut self, config: OpConfig) -> Self {
        self.config = Some(config);
        self
    }
}

impl OpBuilder<Missing> {
    /// Set the OP store, advancing the typestate.
    pub fn store(self, store: Arc<dyn OpStore>) -> OpBuilder<Arc<dyn OpStore>> {
        OpBuilder {
            config: self.config,
            store,
        }
    }
}

impl OpBuilder<Arc<dyn OpStore>> {
    /// Build the `Op` instance. Panics if `config` was not provided.
    pub fn build(self) -> Op<Arc<dyn OpStore>> {
        Op {
            config: self.config.expect("config must be set on OpBuilder"),
            store: self.store,
        }
    }
}
