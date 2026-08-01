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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientRegistration, ClientStore};
    use crate::code::{AuthorizationCode, AuthorizationCodeStore};
    use crate::config::OpConfig;
    use crate::device::{DeviceCodeSession, DeviceCodeStore};
    use crate::error::OpError;
    use crate::refresh::{RefreshToken, RefreshTokenStore};
    use authkestra_engine::auth::session::{Session, SessionStore};
    use authkestra_engine::{Engine, TokenManager};

    struct DummyOpStore;

    #[async_trait::async_trait]
    impl ClientStore for DummyOpStore {
        async fn find_client(&self, _id: &str) -> Result<Option<ClientRegistration>, OpError> {
            Ok(None)
        }
    }
    #[async_trait::async_trait]
    impl AuthorizationCodeStore for DummyOpStore {
        async fn store_code(&self, _code: AuthorizationCode) -> Result<(), OpError> {
            Ok(())
        }
        async fn consume_code(&self, _code: &str) -> Result<Option<AuthorizationCode>, OpError> {
            Ok(None)
        }
    }
    #[async_trait::async_trait]
    impl RefreshTokenStore for DummyOpStore {
        async fn store_token(&self, _t: RefreshToken) -> Result<(), OpError> {
            Ok(())
        }
        async fn consume_token(&self, _t: &str) -> Result<Option<RefreshToken>, OpError> {
            Ok(None)
        }
        async fn get_token(&self, _t: &str) -> Result<Option<RefreshToken>, OpError> {
            Ok(None)
        }
        async fn revoke_token(&self, _t: &str) -> Result<(), OpError> {
            Ok(())
        }
    }
    #[async_trait::async_trait]
    impl DeviceCodeStore for DummyOpStore {
        async fn store_device_code(&self, _s: DeviceCodeSession) -> Result<(), OpError> {
            Ok(())
        }
        async fn get_device_code(&self, _dc: &str) -> Result<Option<DeviceCodeSession>, OpError> {
            Ok(None)
        }
        async fn get_by_user_code(&self, _uc: &str) -> Result<Option<DeviceCodeSession>, OpError> {
            Ok(None)
        }
        async fn update_device_code(&self, _s: DeviceCodeSession) -> Result<(), OpError> {
            Ok(())
        }
        async fn delete_device_code(&self, _dc: &str) -> Result<(), OpError> {
            Ok(())
        }
        async fn consume_device_code(
            &self,
            _dc: &str,
        ) -> Result<Option<DeviceCodeSession>, OpError> {
            Ok(None)
        }
    }
    impl OpStore for DummyOpStore {}

    struct DummySessionStore;
    #[async_trait::async_trait]
    impl SessionStore for DummySessionStore {
        async fn save_session(
            &self,
            _session: &Session,
        ) -> Result<(), authkestra_engine::error::AuthError> {
            Ok(())
        }
        async fn load_session(
            &self,
            _id: &str,
        ) -> Result<Option<Session>, authkestra_engine::error::AuthError> {
            Ok(None)
        }
        async fn delete_session(
            &self,
            _id: &str,
        ) -> Result<(), authkestra_engine::error::AuthError> {
            Ok(())
        }
    }

    #[test]
    fn test_op_builder_flow() {
        let store: Arc<dyn OpStore> = Arc::new(DummyOpStore);
        let session_store: Arc<dyn SessionStore> = Arc::new(DummySessionStore);

        let token_manager = TokenManager::new(
            b"test_secret_key_needs_to_be_32_bytes_long_at_least",
            Some("dummy_issuer".to_string()),
        );

        let engine = Engine::builder()
            .session_store(session_store)
            .token_manager(Arc::new(token_manager))
            .build();

        let config = OpConfig {
            issuer: "http://localhost".to_string(),
            scopes_supported: vec![],
            response_types_supported: vec![],
            grant_types_supported: vec![],
            id_token_signing_alg: "RS256".to_string(),
            authorization_code_ttl_secs: 60,
            access_token_ttl_secs: 3600,
            device_code_ttl_secs: 300,
            token_exchange_enabled: false,
        };

        let op = Op::builder()
            .config(config)
            .engine(engine)
            .store(store)
            .build();

        assert_eq!(op.config.issuer, "http://localhost");
    }
}
