use crate::error::OpError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// OAuth2/OIDC grant types a client may be permitted to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantType {
    /// Standard authorization code grant (with or without PKCE).
    AuthorizationCode,
    /// Refresh token grant.
    RefreshToken,
    /// Client credentials grant (machine-to-machine). See RFC-003 §9, `OP.7`.
    ClientCredentials,
}

/// A registered OAuth2/OIDC client application.
///
/// `redirect_uris` are matched **exactly** (no prefix/wildcard matching) —
/// see RFC-003 §7. This is the single most important invariant in this
/// type; do not relax it for convenience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    /// Public client identifier.
    pub client_id: String,
    /// Hash of the client secret. Never store or log the plaintext secret.
    /// `None` for public clients (e.g. SPAs, native apps using PKCE).
    pub client_secret_hash: Option<String>,
    /// Exact-match redirect URIs this client is permitted to use.
    pub redirect_uris: Vec<String>,
    /// Grant types this client is permitted to use.
    pub grant_types: Vec<GrantType>,
    /// Scopes this client is permitted to request.
    pub scopes: Vec<String>,
    /// Whether this client must use PKCE (mandatory for public clients,
    /// recommended for all — see RFC-003 §7 / OAuth 2.1).
    pub require_pkce: bool,
}

impl ClientRegistration {
    /// Returns true if `redirect_uri` exactly matches one of this client's
    /// registered URIs. Intentionally a plain `==` comparison — no
    /// normalization, no prefix matching.
    pub fn allows_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == redirect_uri)
    }

    /// Returns true if this client is permitted to use `grant_type`.
    pub fn allows_grant_type(&self, grant_type: GrantType) -> bool {
        self.grant_types.contains(&grant_type)
    }
}

/// Storage interface for registered clients.
///
/// Mirrors the existing `SessionStore` pattern in `authkestra-engine`:
/// async trait, pluggable backends, in-memory implementation ships first.
#[async_trait]
pub trait ClientStore: Send + Sync {
    /// Look up a client by its `client_id`. Returns `Ok(None)` (not an
    /// error) if the client does not exist — callers map that to
    /// `OpError::UnknownClient`.
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError>;
}

/// A minimal in-memory `ClientStore`, intended for development and tests —
/// not for production use (no persistence, no distribution across
/// instances). Production deployments should implement `ClientStore`
/// against their own database, the same way `authkestra-session-sql` does
/// for `SessionStore`.
#[derive(Default)]
pub struct InMemoryClientStore {
    clients: RwLock<HashMap<String, ClientRegistration>>,
}

impl InMemoryClientStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a client, replacing any existing registration with the
    /// same `client_id`.
    pub fn register(&self, client: ClientRegistration) {
        self.clients
            .write()
            .expect("client store lock poisoned")
            .insert(client.client_id.clone(), client);
    }
}

#[async_trait]
impl ClientStore for InMemoryClientStore {
    async fn find_client(&self, client_id: &str) -> Result<Option<ClientRegistration>, OpError> {
        Ok(self
            .clients
            .read()
            .map_err(|_| OpError::Storage)?
            .get(client_id)
            .cloned())
    }
}
