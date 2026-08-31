use crate::client::ClientStore;
use authkestra_engine::store::traits::{ClientAssertionStore, NoClientAssertionStore};
use crate::code::AuthorizationCodeStore;
use crate::device::DeviceCodeStore;
use crate::dpop::{DpopReplayStore, NoDpopReplayStore};
use authkestra_engine::store::StoreError;
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
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        NoClientAssertionStore.record_jti(jti, expires_at).await.map_err(Into::into)
    }

    /// Atomically records the `jti` of a presented DPoP proof, returning
    /// `Ok(false)` if it was already spent (RFC 9449 §11.1).
    ///
    /// A defaulted method, same reasoning as `record_client_assertion_jti`:
    /// adding replay tracking must not break every existing `OpStore`
    /// implementation.
    ///
    /// **The default refuses every proof.** See
    /// `record_client_assertion_jti`'s doc comment for why failing closed
    /// is the only safe default here too. See
    /// `CompositeOpStore::with_dpop_replay_store` for how to wire one.
    async fn check_and_record_dpop_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        NoDpopReplayStore
            .check_and_record_dpop_jti(jti, expires_at)
            .await.map_err(Into::into)
    }

    /// Handle a custom grant type request during token exchange.
    ///
    /// By default, this returns an `unsupported_grant_type` error.
    async fn handle_custom_grant(
        &mut self,
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

    /// Handle an `authorization_code` grant (RFC 6749 §4.1) request during
    /// token exchange.
    ///
    /// A defaulted method, same reasoning as `handle_refresh_token` and
    /// `handle_token_exchange` below: the built-in dispatch in
    /// `handlers::token::handle_token` used to match the literal string
    /// `"authorization_code"` and call straight into the built-in handler,
    /// with no seam an `OpStore` implementor could intercept. That made it
    /// impossible to stamp custom claims onto, or create session state for,
    /// tokens issued by the authorization-code flow — e.g.
    /// `TokenManager::issue_user_token_with_extra` exists precisely for
    /// this, but the built-in handler had no way to reach it — without
    /// forking the crate.
    ///
    /// The default (see `default_handle_authorization_code`) reproduces the
    /// existing authorization-code exchange logic (code consumption, PKCE
    /// verification, redirect_uri/client_id validation, and token
    /// issuance). Any `OpStore` that does not override this method gets
    /// that behavior automatically; nothing about the trait or dispatch
    /// changes for it.
    async fn handle_authorization_code_grant(
        &mut self,
        req: crate::handlers::token::TokenRequest,
        client_id: String,
        client: crate::client::ClientRegistration,
        config: &crate::config::OpConfig,
        tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<crate::handlers::token::TokenResponse, crate::handlers::token::TokenErrorResponse>
    {
        crate::handlers::token::default_handle_authorization_code(
            req, client_id, client, config, self, tokens,
        )
        .await.map_err(Into::into)
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
    /// The default (see `default_handle_refresh_token`) consumes and
    /// rotates the refresh token, re-mints an access token, and — mirroring
    /// `default_handle_authorization_code` — re-mints an `id_token` too when
    /// the stored scope includes `openid` (OIDC Core §12.2 makes this
    /// optional; this crate now exercises that option instead of always
    /// omitting it).
    /// Any `OpStore` that does not override this method gets that behavior
    /// automatically; nothing about the trait or dispatch changes for it.
    async fn handle_refresh_token(
        &mut self,
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
        .await.map_err(Into::into)
    }

    /// Handle a `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693)
    /// grant request during token exchange.
    ///
    /// A defaulted method, same reasoning as `handle_refresh_token`: the
    /// built-in dispatch in `handlers::token::handle_token` used to call the
    /// built-in handler directly, with no seam an `OpStore` implementor could
    /// intercept. That made it impossible to stamp custom claims onto the
    /// exchanged token — e.g. `TokenManager::issue_user_token_with_extra`
    /// exists precisely for this, but the built-in handler had no way to
    /// reach it — without forking the crate.
    ///
    /// The default (see `default_handle_token_exchange`) reproduces the
    /// existing exchange logic. Any `OpStore` that does not override this
    /// method gets that behavior automatically; nothing about the trait or
    /// dispatch changes for it.
    async fn handle_token_exchange(
        &mut self,
        req: crate::handlers::token::TokenRequest,
        client_id: String,
        client: crate::client::ClientRegistration,
        config: &crate::config::OpConfig,
        tokens: &authkestra_engine::token::TokenManager,
    ) -> Result<crate::handlers::token::TokenResponse, crate::handlers::token::TokenErrorResponse>
    {
        crate::handlers::token::default_handle_token_exchange(
            req, client_id, client, config, tokens,
        )
        .await.map_err(Into::into)
    }
}

/// A helper struct that implements `OpStore` by delegating to individual stores.
/// Useful if you want to use different backends for different types of data (e.g., config for clients, Redis for codes).
///
/// The client-assertion and DPoP-replay slots default to
/// [`NoClientAssertionStore`] and [`NoDpopReplayStore`] respectively, so
/// `private_key_jwt` and DPoP are both refused until a deployment opts in
/// with [`CompositeOpStore::with_client_assertion_store`] /
/// [`CompositeOpStore::with_dpop_replay_store`]. Both are defaulted type
/// parameters rather than required arguments to [`CompositeOpStore::new`]
/// so that existing four-store call sites keep compiling untouched.
#[non_exhaustive]
pub struct CompositeOpStore<C, A, R, D, J = NoClientAssertionStore, P = NoDpopReplayStore> {
    clients: C,
    codes: A,
    refresh: R,
    devices: D,
    assertions: J,
    dpop_replays: P,
}

#[async_trait::async_trait]
impl<C, A, R, D, J, P> OpStore for CompositeOpStore<C, A, R, D, J, P>
where
    C: ClientStore,
    A: AuthorizationCodeStore,
    R: RefreshTokenStore,
    D: DeviceCodeStore,
    J: ClientAssertionStore,
    P: DpopReplayStore,
    Self: Send + Sync,
{
    async fn record_client_assertion_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        self.assertions.record_jti(jti, expires_at).await.map_err(Into::into)
    }

    async fn check_and_record_dpop_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, authkestra_engine::store::StoreError> {
        self.dpop_replays
            .check_and_record_dpop_jti(jti, expires_at)
            .await.map_err(Into::into)
    }
}

impl<C, A, R, D> CompositeOpStore<C, A, R, D, NoClientAssertionStore, NoDpopReplayStore> {
    /// Create a new `CompositeOpStore` from individual stores.
    pub fn new(clients: C, codes: A, refresh: R, devices: D) -> Self {
        Self {
            clients,
            codes,
            refresh,
            devices,
            assertions: NoClientAssertionStore,
            dpop_replays: NoDpopReplayStore,
        }
    }
}

impl<C, A, R, D, J, P> CompositeOpStore<C, A, R, D, J, P> {
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
    ) -> CompositeOpStore<C, A, R, D, J2, P> {
        CompositeOpStore {
            clients: self.clients,
            codes: self.codes,
            refresh: self.refresh,
            devices: self.devices,
            assertions,
            dpop_replays: self.dpop_replays,
        }
    }

    /// Swaps in the backend that tracks spent DPoP proof `jti`s — the one
    /// thing this store needs before it will accept a `DPoP` header at
    /// `/token` at all.
    ///
    /// Any backend `authkestra_engine::store::AtomicInsert` is implemented
    /// for (`MemoryStore`, `RedisStore`, and the SQL backends) already
    /// implements [`crate::dpop::DpopReplayStore`] via its blanket impl — no
    /// DPoP-specific storage code is needed. A single-node deployment can
    /// use `authkestra_engine::store::memory::MemoryStore`; a cluster needs
    /// something shared, for the same reason `with_client_assertion_store`
    /// does.
    pub fn with_dpop_replay_store<P2: DpopReplayStore>(
        self,
        dpop_replays: P2,
    ) -> CompositeOpStore<C, A, R, D, J, P2> {
        CompositeOpStore {
            clients: self.clients,
            codes: self.codes,
            refresh: self.refresh,
            devices: self.devices,
            assertions: self.assertions,
            dpop_replays,
        }
    }
}

#[async_trait::async_trait]
impl<
        C: ClientStore,
        A: Send + Sync,
        R: Send + Sync,
        D: Send + Sync,
        J: Send + Sync,
        P: Send + Sync,
    > ClientStore for CompositeOpStore<C, A, R, D, J, P>
{
    #[tracing::instrument(skip(self))]
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<crate::client::ClientRegistration>, authkestra_engine::store::StoreError> {
        tracing::debug!(client_id = %client_id, "CompositeOpStore: finding client");
        self.clients.find_client(client_id).await.map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl<
        C: Send + Sync,
        A: AuthorizationCodeStore,
        R: Send + Sync,
        D: Send + Sync,
        J: Send + Sync,
        P: Send + Sync,
    > AuthorizationCodeStore for CompositeOpStore<C, A, R, D, J, P>
{
    #[tracing::instrument(skip(self, code))]
    async fn store_code(
        &mut self,
        code: crate::code::AuthorizationCode,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: storing authorization code");
        self.codes.store_code(code).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    async fn consume_code(
        &mut self,
        code: &str,
    ) -> Result<Option<crate::code::AuthorizationCode>, authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: consuming authorization code");
        self.codes.consume_code(code).await.map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl<
        C: Send + Sync,
        A: Send + Sync,
        R: RefreshTokenStore,
        D: Send + Sync,
        J: Send + Sync,
        P: Send + Sync,
    > RefreshTokenStore for CompositeOpStore<C, A, R, D, J, P>
{
    #[tracing::instrument(skip(self, token))]
    async fn store_token(
        &mut self,
        token: crate::refresh::RefreshToken,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: storing refresh token");
        self.refresh.store_token(token).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    async fn consume_token(
        &mut self,
        token: &str,
    ) -> Result<Option<crate::refresh::RefreshToken>, authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: consuming refresh token");
        self.refresh.consume_token(token).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    async fn get_token(
        &mut self,
        token: &str,
    ) -> Result<Option<crate::refresh::RefreshToken>, authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: getting refresh token");
        self.refresh.get_token(token).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    async fn revoke_token(&mut self, token: &str) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: revoking refresh token");
        self.refresh.revoke_token(token).await.map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl<
        C: Send + Sync,
        A: Send + Sync,
        R: Send + Sync,
        D: DeviceCodeStore,
        J: Send + Sync,
        P: Send + Sync,
    > DeviceCodeStore for CompositeOpStore<C, A, R, D, J, P>
{
    #[tracing::instrument(skip(self, session))]
    async fn store_device_code(
        &mut self,
        session: crate::device::DeviceCodeSession,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: storing device code");
        self.devices.store_device_code(session).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError> {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: getting device code");
        self.devices.get_device_code(device_code).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError> {
        tracing::debug!(user_code = %user_code, "CompositeOpStore: getting by user code");
        self.devices.get_by_user_code(user_code).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self, session))]
    async fn update_device_code(
        &mut self,
        session: crate::device::DeviceCodeSession,
    ) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!("CompositeOpStore: updating device code");
        self.devices.update_device_code(session).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), authkestra_engine::store::StoreError> {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: deleting device code");
        self.devices.delete_device_code(device_code).await.map_err(Into::into)
    }

    #[tracing::instrument(skip(self))]
    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, authkestra_engine::store::StoreError> {
        tracing::debug!(device_code = %device_code, "CompositeOpStore: consuming device code");
        self.devices.consume_device_code(device_code).await.map_err(Into::into)
    }
}
