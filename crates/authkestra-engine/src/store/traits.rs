use crate::oauth2::client::ClientRegistration;
use crate::oauth2::code::AuthorizationCode;
use crate::oauth2::device::DeviceCodeSession;
use crate::oauth2::refresh::RefreshToken;
use crate::store::StoreError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait ClientStore: Send + Sync {
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError>;
}

#[async_trait]
pub trait AuthorizationCodeStore: Send + Sync {
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError>;
    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError>;
}

#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError>;
    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError>;
    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError>;
    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError>;
}

#[async_trait]
pub trait DeviceCodeStore: Send + Sync {
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError>;
    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError>;
    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError>;
    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError>;
    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError>;
    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError>;
}

#[async_trait]
pub trait ClientAssertionStore: Send + Sync {
    async fn record_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;
}

#[async_trait]
pub trait DpopReplayStore: Send + Sync {
    async fn check_and_record_dpop_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;
}

pub struct NoClientAssertionStore;
#[async_trait]
impl ClientAssertionStore for NoClientAssertionStore {
    async fn record_jti(
        &mut self,
        _jti: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        Ok(false)
    }
}

#[async_trait]
pub trait OpStore:
    ClientStore + AuthorizationCodeStore + RefreshTokenStore + DeviceCodeStore + Send + Sync
{
    async fn record_client_assertion_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        NoClientAssertionStore.record_jti(jti, expires_at).await
    }

    async fn check_and_record_dpop_jti(
        &mut self,
        _jti: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        Ok(true)
    }
}

use crate::store::{AtomicConsume, AtomicInsert, IndexedKvStore, KvStore};

#[async_trait]
impl<S> ClientStore for S
where
    S: KvStore<ClientRegistration> + Send + Sync,
{
    async fn find_client(
        &mut self,
        client_id: &str,
    ) -> Result<Option<ClientRegistration>, StoreError> {
        self.get(client_id).await
    }
}

#[async_trait]
impl<S> AuthorizationCodeStore for S
where
    S: KvStore<AuthorizationCode> + AtomicConsume<AuthorizationCode> + Send + Sync,
{
    async fn store_code(&mut self, code: AuthorizationCode) -> Result<(), StoreError> {
        let ttl = code
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(1));
        self.set(&code.code.clone(), code, ttl).await
    }

    async fn consume_code(&mut self, code: &str) -> Result<Option<AuthorizationCode>, StoreError> {
        self.consume(code).await
    }
}

#[async_trait]
impl<S> RefreshTokenStore for S
where
    S: KvStore<RefreshToken> + AtomicConsume<RefreshToken> + Send + Sync,
{
    async fn store_token(&mut self, token: RefreshToken) -> Result<(), StoreError> {
        let ttl = token
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(1));
        self.set(&token.token.clone(), token, ttl).await
    }

    async fn get_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        self.get(token).await
    }

    async fn revoke_token(&mut self, token: &str) -> Result<(), StoreError> {
        self.delete(token).await
    }

    async fn consume_token(&mut self, token: &str) -> Result<Option<RefreshToken>, StoreError> {
        self.consume(token).await
    }
}

#[async_trait]
impl<S> DeviceCodeStore for S
where
    S: IndexedKvStore<DeviceCodeSession> + AtomicConsume<DeviceCodeSession> + Send + Sync,
{
    async fn store_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let ttl = session
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(1));
        self.set_indexed(
            &session.device_code.clone(),
            &session.user_code.clone(),
            session,
            ttl,
        )
        .await
    }

    async fn get_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        self.get(device_code).await
    }

    async fn get_by_user_code(
        &mut self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        self.get_by_index(user_code).await
    }

    async fn update_device_code(&mut self, session: DeviceCodeSession) -> Result<(), StoreError> {
        let ttl = session
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(1));
        self.set_indexed(
            &session.device_code.clone(),
            &session.user_code.clone(),
            session,
            ttl,
        )
        .await
    }

    async fn delete_device_code(&mut self, device_code: &str) -> Result<(), StoreError> {
        self.delete(device_code).await
    }

    async fn consume_device_code(
        &mut self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, StoreError> {
        self.consume(device_code).await
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct DpopJtiRecord {
    pub jti: String,
    pub expires_at: DateTime<Utc>,
}

impl DpopJtiRecord {
    pub fn new(jti: String, expires_at: DateTime<Utc>) -> Self {
        Self { jti, expires_at }
    }
}

pub struct NoDpopReplayStore;
#[async_trait]
impl DpopReplayStore for NoDpopReplayStore {
    async fn check_and_record_dpop_jti(
        &mut self,
        _jti: &str,
        _expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        tracing::error!("a DPoP proof was presented but no DpopReplayStore is wired; refusing it rather than accepting a proof that could be replayed");
        Err(StoreError::Internal(
            "DpopReplayProtectionUnavailable".into(),
        ))
    }
}

#[async_trait]
impl<S> DpopReplayStore for S
where
    S: KvStore<DpopJtiRecord> + AtomicInsert<DpopJtiRecord> + Send + Sync,
{
    async fn check_and_record_dpop_jti(
        &mut self,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        tracing::trace!("attempting to record dpop proof jti");
        let ttl = expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(0));

        self.insert_if_absent(jti, DpopJtiRecord::new(jti.to_string(), expires_at), ttl)
            .await
    }
}
