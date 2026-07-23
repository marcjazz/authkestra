//! # Authkestra Flow
//!
//! `authkestra-flow` orchestrates authentication flows, such as OAuth2 Authorization Code,
//! PKCE, Client Credentials, and Device Flow. It acts as the bridge between the core traits
//! and the framework-specific adapters.
//!
//! ## Key Components
//!
//! - **[`OAuth2Flow`]**: Orchestrates the standard OAuth2 Authorization Code flow.
//! - **[`Authkestra`]**: The main service that holds providers, session stores, and token managers.
//! - **[`AuthkestraBuilder`]**: A builder for configuring and creating an [`Authkestra`] instance.
//! - **[`CredentialsFlow`]**: Orchestrates direct credentials-based authentication (e.g., email/password).

#![warn(missing_docs)]

use crate::auth::{error::AuthError, state::Identity, CredentialsProvider, UserMapper};
pub use crate::auth::{ErasedOAuthFlow, Session, SessionConfig, SessionStore};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub use chrono;

/// Context for an authentication flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

pub use crate::engine::{AkBase, AkEngineBuilder, Configured, Missing};

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
