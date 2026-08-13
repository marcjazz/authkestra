use crate::client::ClientStore;
use crate::client_assertion::{ClientAssertionStore, NoClientAssertionStore};
use crate::code::AuthorizationCodeStore;
use crate::device::DeviceCodeStore;
use crate::error::OpError;
use crate::refresh::RefreshTokenStore;
use chrono::{DateTime, Utc};

/// A unified store for all OpenID Provider state.
/// This supertrait aggregates `ClientStore`, `AuthorizationCodeStore`,
/// `RefreshTokenStore`, and `DeviceCodeStore`.
#[async_trait::async_trait]
pub trait OpStore:
    ClientStore + AuthorizationCodeStore + RefreshTokenStore + DeviceCodeStore + Send + Sync
{
    /// Atomically spends the `jti` of a `private_key_jwt` client assertion,
    /// returning `Ok(false)` if it was already spent (RFC 7523 §3 point 7).
    ///
    /// A defaulted method rather than a fifth supertrait, so that adding
    /// replay tracking does not break every existing `OpStore`
    /// implementation — the same reasoning that makes `handle_custom_grant`
    /// a defaulted method here.
    ///
    /// **The default refuses every assertion.** A store that has not
    /// implemented `jti` tracking cannot offer the single-use guarantee, and
    /// a `private_key_jwt` deployment without it would be strictly worse than
    /// one without the method at all: the client would believe it had
    /// proof-of-possession authentication while a captured assertion stayed
    /// replayable for its whole lifetime. Failing closed makes that
    /// impossible to reach by accident. See
    /// `CompositeOpStore::with_client_assertion_store` for how to wire one.
    async fn record_client_assertion_jti(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, OpError> {
        NoClientAssertionStore.record_jti(jti, expires_at).await
    }

    /// Handle a custom grant type request during token exchange.
    ///
    /// By default, this returns an `unsupported_grant_type` error.
    async fn handle_custom_grant(
        &self,
        _grant_type: &str,
        _req: crate::handlers::token::TokenRequest,
        _client_id: String,
        _client: crate::client::ClientRegistration,
        _config: &crate::config::OpConfig,
        _tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<crate::handlers::token::TokenResponse, crate::handlers::token::TokenErrorResponse>
    {
        Err(crate::handlers::token::TokenErrorResponse {
            error: "unsupported_grant_type".to_string(),
            error_description: "Unsupported grant type".to_string(),
        })
    }

    /// Handle a `refresh_token` grant request during token exchange.
    ///
    /// A defaulted method, same reasoning as `handle_custom_grant`: the
    /// built-in dispatch in `handlers::token::handle_token` used to match the
    /// literal string `"refresh_token"` and call straight into the built-in
    /// handler, with no seam an `OpStore` implementor could intercept. That
    /// made it impossible to substitute custom refresh behavior — e.g.
    /// re-minting an `id_token`, or a non-default rotation policy — without
    /// forking the crate.
    ///
    /// **The default reproduces today's built-in behavior exactly** —
    /// consume-and-rotate the refresh token and re-mint an access token
    /// (see `default_handle_refresh_token`). Any `OpStore` that does not
    /// override this method behaves identically to before this method
    /// existed.
    async fn handle_refresh_token(
        &self,
        req: crate::handlers::token::TokenRequest,
        client_id: String,
        client: crate::client::ClientRegistration,
        config: &crate::config::OpConfig,
        tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<crate::handlers::token::TokenResponse, crate::handlers::token::TokenErrorResponse>
    {
        crate::handlers::token::default_handle_refresh_token(
            req, client_id, client, config, self, tokens,
        )
        .await
    }
}

/// A helper struct that implements `OpStore` by delegating to 5 individual stores.
/// Useful if you want to use different backends for different types of data (e.g., config for clients, Redis for codes).
///
/// The client-assertion slot defaults to
/// [`NoClientAssertionStore`], so `private_key_jwt` is refused until a
/// deployment opts in with [`CompositeOpStore::with_client_assertion_store`].
/// It is a defaulted type parameter rather than a fifth argument to
/// [`CompositeOpStore::new`] so that existing four-store call sites keep
/// compiling untouched.
pub struct CompositeOpStore<C, A, R, D, J = NoClientAssertionStore> {
    clients: C,
    codes: A,
    refresh: R,
    devices: D,
    assertions: J,
}

#[async_trait::async_trait]
impl<C, A, R, D, J> OpStore for CompositeOpStore<C, A, R, D, J>
where
    C: ClientStore,
    A: AuthorizationCodeStore,
    R: RefreshTokenStore,
    D: DeviceCodeStore,
    J: ClientAssertionStore,
    Self: Send + Sync,
{
    async fn record_client_assertion_jti(
        &self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, OpError> {
        self.assertions.record_jti(jti, expires_at).await
    }
}

impl<C, A, R, D> CompositeOpStore<C, A, R, D, NoClientAssertionStore> {
    /// Create a new `CompositeOpStore` from individual stores.
    pub fn new(clients: C, codes: A, refresh: R, devices: D) -> Self {
        Self {
            clients,
            codes,
            refresh,
            devices,
            assertions: NoClientAssertionStore,
        }
    }
}

impl<C, A, R, D, J> CompositeOpStore<C, A, R, D, J> {
    /// Swaps in the backend that tracks spent `private_key_jwt` assertion
    /// `jti`s — the one thing this store needs before it will accept
    /// asymmetric client authentication at all.
    ///
    /// [`crate::client_assertion::MemoryClientAssertionStore`] is correct for
    /// a single-node deployment; a cluster needs something shared, because an
    /// unshared map means one accepted replay per node. Whichever is chosen,
    /// remember to advertise the method with
    /// [`crate::handlers::discovery::OidcDiscovery::with_private_key_jwt`] —
    /// discovery is deliberately silent about it otherwise.
    pub fn with_client_assertion_store<J2: ClientAssertionStore>(
        self,
        assertions: J2,
    ) -> CompositeOpStore<C, A, R, D, J2> {
        CompositeOpStore {
            clients: self.clients,
            codes: self.codes,
            refresh: self.refresh,
            devices: self.devices,
            assertions,
        }
    }
}

#[async_trait::async_trait]
impl<C: ClientStore, A: Send + Sync, R: Send + Sync, D: Send + Sync, J: Send + Sync> ClientStore
    for CompositeOpStore<C, A, R, D, J>
{
    #[tracing::instrument(skip(self))]
    async fn find_client(
        &self,
        client_id: &str,
    ) -> Result<Option<crate::client::ClientRegistration>, crate::error::OpError> {
        tracing::debug!(client_id = %client_id, "CompositeOpStore: finding client");
        self.clients.find_client(client_id).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: AuthorizationCodeStore, R: Send + Sync, D: Send + Sync, J: Send + Sync>
    AuthorizationCodeStore for CompositeOpStore<C, A, R, D, J>
{
    #[tracing::instrument(skip(self, code))]
    async fn store_code(
        &self,
        code: crate::code::AuthorizationCode,
    ) -> Result<(), crate::error::OpError> {
        tracing::debug!("CompositeOpStore: storing authorization code");
        self.codes.store_code(code).await
    }

    #[tracing::instrument(skip(self))]
    async fn consume_code(
        &self,
        code: &str,
    ) -> Result<Option<crate::code::AuthorizationCode>, crate::error::OpError> {
        tracing::debug!("CompositeOpStore: consuming authorization code");
        self.codes.consume_code(code).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: Send + Sync, R: RefreshTokenStore, D: Send + Sync, J: Send + Sync>
    RefreshTokenStore for CompositeOpStore<C, A, R, D, J>
{
    #[tracing::instrument(skip(self, token))]
    async fn store_token(
        &self,
        token: crate::refresh::RefreshToken,
    ) -> Result<(), crate::error::OpError> {
        tracing::debug!("CompositeOpStore: storing refresh token");
        self.refresh.store_token(token).await
    }

    #[tracing::instrument(skip(self))]
    async fn consume_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::refresh::RefreshToken>, crate::error::OpError> {
        tracing::debug!("CompositeOpStore: consuming refresh token");
        self.refresh.consume_token(token).await
    }

    #[tracing::instrument(skip(self))]
    async fn get_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::refresh::RefreshToken>, crate::error::OpError> {
        tracing::debug!("CompositeOpStore: getting refresh token");
        self.refresh.get_token(token).await
    }

    #[tracing::instrument(skip(self))]
    async fn revoke_token(&self, token: &str) -> Result<(), crate::error::OpError> {
        tracing::debug!("CompositeOpStore: revoking refresh token");
        self.refresh.revoke_token(token).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: Send + Sync, R: Send + Sync, D: DeviceCodeStore, J: Send + Sync>
    DeviceCodeStore for CompositeOpStore<C, A, R, D, J>
{
    #[tracing::instrument(skip(self, session))]
    async fn store_device_code(
        &self,
        session: crate::device::DeviceCodeSession,
    ) -> Result<(), crate::error::OpError> {
        tracing::debug!("CompositeOpStore: storing device code");
        self.devices.store_device_code(session).await
    }

    #[tracing::instrument(skip(self))]
    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, crate::error::OpError> {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: getting device code");
        self.devices.get_device_code(device_code).await
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, crate::error::OpError> {
        tracing::debug!(user_code = %user_code, "CompositeOpStore: getting by user code");
        self.devices.get_by_user_code(user_code).await
    }

    #[tracing::instrument(skip(self, session))]
    async fn update_device_code(
        &self,
        session: crate::device::DeviceCodeSession,
    ) -> Result<(), crate::error::OpError> {
        tracing::debug!("CompositeOpStore: updating device code");
        self.devices.update_device_code(session).await
    }

    #[tracing::instrument(skip(self))]
    async fn delete_device_code(&self, device_code: &str) -> Result<(), crate::error::OpError> {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: deleting device code");
        self.devices.delete_device_code(device_code).await
    }

    #[tracing::instrument(skip(self))]
    async fn consume_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, crate::error::OpError> {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: consuming device code");
        self.devices.consume_device_code(device_code).await
    }
}
