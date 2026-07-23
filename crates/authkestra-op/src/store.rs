use crate::client::ClientStore;
use crate::code::AuthorizationCodeStore;
use crate::device::DeviceCodeStore;
use crate::refresh::RefreshTokenStore;

/// A unified store for all OpenID Provider state.
/// This supertrait aggregates `ClientStore`, `AuthorizationCodeStore`,
/// `RefreshTokenStore`, and `DeviceCodeStore`.
pub trait OpStore:
    ClientStore + AuthorizationCodeStore + RefreshTokenStore + DeviceCodeStore + Send + Sync
{
}

// Automatically implement `OpStore` for any type that implements the granular traits.
impl<T> OpStore for T where
    T: ClientStore + AuthorizationCodeStore + RefreshTokenStore + DeviceCodeStore + Send + Sync
{
}

/// A helper struct that implements `OpStore` by delegating to 4 individual stores.
/// Useful if you want to use different backends for different types of data (e.g., config for clients, Redis for codes).
pub struct CompositeOpStore<C, A, R, D> {
    clients: C,
    codes: A,
    refresh: R,
    devices: D,
}

impl<C, A, R, D> CompositeOpStore<C, A, R, D> {
    /// Create a new `CompositeOpStore` from individual stores.
    pub fn new(clients: C, codes: A, refresh: R, devices: D) -> Self {
        Self {
            clients,
            codes,
            refresh,
            devices,
        }
    }
}

#[async_trait::async_trait]
impl<C: ClientStore, A: Send + Sync, R: Send + Sync, D: Send + Sync> ClientStore
    for CompositeOpStore<C, A, R, D>
{
    async fn find_client(
        &self,
        client_id: &str,
    ) -> Result<Option<crate::client::ClientRegistration>, crate::error::OpError> {
        self.clients.find_client(client_id).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: AuthorizationCodeStore, R: Send + Sync, D: Send + Sync>
    AuthorizationCodeStore for CompositeOpStore<C, A, R, D>
{
    async fn store_code(
        &self,
        code: crate::code::AuthorizationCode,
    ) -> Result<(), crate::error::OpError> {
        self.codes.store_code(code).await
    }

    async fn consume_code(
        &self,
        code: &str,
    ) -> Result<Option<crate::code::AuthorizationCode>, crate::error::OpError> {
        self.codes.consume_code(code).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: Send + Sync, R: RefreshTokenStore, D: Send + Sync> RefreshTokenStore
    for CompositeOpStore<C, A, R, D>
{
    async fn store_token(
        &self,
        token: crate::refresh::RefreshToken,
    ) -> Result<(), crate::error::OpError> {
        self.refresh.store_token(token).await
    }

    async fn consume_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::refresh::RefreshToken>, crate::error::OpError> {
        self.refresh.consume_token(token).await
    }

    async fn get_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::refresh::RefreshToken>, crate::error::OpError> {
        self.refresh.get_token(token).await
    }

    async fn revoke_token(&self, token: &str) -> Result<(), crate::error::OpError> {
        self.refresh.revoke_token(token).await
    }
}

#[async_trait::async_trait]
impl<C: Send + Sync, A: Send + Sync, R: Send + Sync, D: DeviceCodeStore> DeviceCodeStore
    for CompositeOpStore<C, A, R, D>
{
    async fn store_device_code(
        &self,
        session: crate::device::DeviceCodeSession,
    ) -> Result<(), crate::error::OpError> {
        self.devices.store_device_code(session).await
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, crate::error::OpError> {
        self.devices.get_device_code(device_code).await
    }

    async fn get_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, crate::error::OpError> {
        self.devices.get_by_user_code(user_code).await
    }

    async fn update_device_code(
        &self,
        session: crate::device::DeviceCodeSession,
    ) -> Result<(), crate::error::OpError> {
        self.devices.update_device_code(session).await
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<(), crate::error::OpError> {
        self.devices.delete_device_code(device_code).await
    }

    async fn consume_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<crate::device::DeviceCodeSession>, crate::error::OpError> {
        self.devices.consume_device_code(device_code).await
    }
}
