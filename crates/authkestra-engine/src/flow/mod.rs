//! # Engine Flow
//!
//! `authkestra-flow` orchestrates authentication flows, such as OAuth2 Authorization Code,
//! PKCE, Client Credentials, and Device Flow. It acts as the bridge between the core traits
//! and the framework-specific adapters.
//!
//! ## Key Components
//!
//! - **[`OAuth2Flow`]**: Orchestrates the standard OAuth2 Authorization Code flow.
//! - **[`Engine`]**: The main service that holds providers, session stores, and token managers.
//! - **[`EngineBuilder`]**: A builder for configuring and creating an [`Engine`] instance.
//! - **[`CredentialsFlow`]**: Orchestrates direct credentials-based authentication (e.g., email/password).

#![warn(missing_docs)]

use crate::auth::{error::AuthError, state::Identity, CredentialsProvider, UserMapper};
pub use crate::auth::{ErasedOAuthFlow, Session, SessionConfig, SessionStore};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use chrono;

/// Context for an authentication flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FlowContext {
    /// The current state identifier.
    pub state: String,
    /// Parameters associated with the flow.
    pub params: HashMap<String, String>,
}

/// Result of an authentication flow execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FlowResult {
    /// The flow is complete and has returned an identity.
    Complete(Identity),
    /// The flow requires a redirect to another URL.
    Redirect(String),
    /// The flow is pending (e.g., waiting for user interaction).
    Pending,
}

/// Orchestrates the steps of an authentication protocol (e.g., OAuth2, Device Flow).
#[async_trait]
pub trait Flow: Send + Sync {
    /// Returns the unique identifier for the flow.
    fn id(&self) -> &str;

    /// Executes the flow with the given context.
    async fn execute(&self, ctx: FlowContext) -> Result<FlowResult, AuthError>;
}

use std::collections::HashMap;

pub use crate::engine::{Configured, Engine, EngineBuilder, Missing};

/// Client Credentials flow implementation.
pub mod client_credentials_flow;
/// Device Authorization flow implementation.
pub mod device_flow;
/// OAuth2 Authorization Code flow implementation.
pub mod oauth2;

pub use client_credentials_flow::ClientCredentialsFlow;
pub use device_flow::{DeviceAuthorizationResponse, DeviceFlow};
pub use oauth2::OAuth2Flow;

/// Orchestrates a direct credentials flow.
#[non_exhaustive]
pub struct CredentialsFlow<P: CredentialsProvider, M: UserMapper = ()> {
    provider: P,
    mapper: Option<M>,
}

impl<P: CredentialsProvider> CredentialsFlow<P, ()> {
    /// Create a new `CredentialsFlow` with the given provider.
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            mapper: None,
        }
    }
}

impl<P: CredentialsProvider, M: UserMapper> CredentialsFlow<P, M> {
    /// Create a new `CredentialsFlow` with the given provider and user mapper.
    pub fn with_mapper(provider: P, mapper: M) -> Self {
        Self {
            provider,
            mapper: Some(mapper),
        }
    }

    /// Authenticate using the given credentials.
    pub async fn authenticate(
        &self,
        creds: P::Credentials,
    ) -> Result<(Identity, Option<M::LocalUser>), AuthError> {
        let identity = self.provider.authenticate(creds).await?;

        let local_user = if let Some(mapper) = &self.mapper {
            Some(mapper.map_user(&identity).await?)
        } else {
            None
        };

        Ok((identity, local_user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    #[derive(Debug, PartialEq, Clone)]
    struct DummyCreds(String);

    struct DummyProvider;
    #[async_trait]
    impl CredentialsProvider for DummyProvider {
        type Credentials = DummyCreds;
        async fn authenticate(&self, creds: Self::Credentials) -> Result<Identity, AuthError> {
            if creds.0 == "valid" {
                Ok(Identity {
                    provider_id: "dummy".to_string(),
                    external_id: "user_123".to_string(),
                    email: None,
                    username: None,
                    attributes: std::collections::HashMap::new(),
                })
            } else {
                Err(AuthError::InvalidCredentials)
            }
        }
    }

    #[derive(Debug, PartialEq)]
    struct DummyUser(String);

    struct DummyMapper;
    #[async_trait]
    impl UserMapper for DummyMapper {
        type LocalUser = DummyUser;
        async fn map_user(&self, identity: &Identity) -> Result<Self::LocalUser, AuthError> {
            Ok(DummyUser(identity.external_id.clone()))
        }
    }

    #[tokio::test]
    async fn test_credentials_flow() {
        let flow = CredentialsFlow::new(DummyProvider);
        let res = flow
            .authenticate(DummyCreds("valid".to_string()))
            .await
            .unwrap();
        assert_eq!(res.0.external_id, "user_123");
        assert!(res.1.is_none());

        let err = flow.authenticate(DummyCreds("invalid".to_string())).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_credentials_flow_with_mapper() {
        let flow = CredentialsFlow::with_mapper(DummyProvider, DummyMapper);
        let res = flow
            .authenticate(DummyCreds("valid".to_string()))
            .await
            .unwrap();
        assert_eq!(res.0.external_id, "user_123");
        assert_eq!(res.1.unwrap(), DummyUser("user_123".to_string()));
    }
}
