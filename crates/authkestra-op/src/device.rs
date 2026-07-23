use crate::error::OpError;
use async_trait::async_trait;
use authkestra_engine::auth::state::Identity;
use authkestra_engine::store::KvStore;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents the current status of a device authorization code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceCodeStatus {
    /// The device code has been issued, but the user has not yet approved it.
    Pending,
    /// The user has approved the device code and authorized the requested scopes.
    Approved(Identity),
    /// The user denied the authorization request.
    Denied,
}

/// Represents a device authorization session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeSession {
    /// The device verification code.
    pub device_code: String,
    /// The end-user verification code.
    pub user_code: String,
    /// The client identifier.
    pub client_id: String,
    /// The requested scopes.
    pub scope: String,
    /// The time at which the device code expires.
    pub expires_at: DateTime<Utc>,
    /// The current status of the authorization request.
    pub status: DeviceCodeStatus,
    /// The last time the client polled the token endpoint.
    pub last_polled_at: Option<DateTime<Utc>>,
}

impl DeviceCodeSession {
    /// Checks if the device code session is expired.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}

/// Trait for storing device codes.
#[async_trait]
pub trait DeviceCodeStore: Send + Sync {
    /// Store a new device code session.
    async fn store_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError>;
    /// Get a device code session by the device code.
    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError>;
    /// Get a device code session by the user code.
    async fn get_by_user_code(&self, user_code: &str)
        -> Result<Option<DeviceCodeSession>, OpError>;
    /// Update an existing device code session.
    async fn update_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError>;
    /// Delete a device code session.
    async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError>;
    /// Atomically consume (get and delete) a device code session.
    async fn consume_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError>;
}

use authkestra_engine::store::{AtomicConsume, IndexedKvStore};
use std::time::Duration;

#[async_trait]
impl<S> DeviceCodeStore for S
where
    S: IndexedKvStore<DeviceCodeSession> + AtomicConsume<DeviceCodeSession>,
{
    async fn store_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        // Keep the token in the store for 5 minutes after expiration
        // so that the token endpoint can explicitly return `expired_token`
        // instead of `invalid_grant`.
        let ttl = session
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0))
            + Duration::from_secs(300);

        let device_code = session.device_code.clone();
        let user_code = session.user_code.clone();

        self.set_indexed(&device_code, &user_code, session, ttl)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "failed to store device code");
                OpError::Storage
            })
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.get(device_code).await.map_err(|e| {
            tracing::error!(error = %e, "failed to get device code");
            OpError::Storage
        })
    }

    async fn get_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.get_by_index(user_code).await.map_err(|e| {
            tracing::error!(error = %e, "failed to get device code by user code");
            OpError::Storage
        })
    }

    async fn update_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        // Keep the token in the store for 5 minutes after expiration
        let ttl = session
            .expires_at
            .signed_duration_since(Utc::now())
            .to_std()
            .unwrap_or(Duration::from_secs(0))
            + Duration::from_secs(300);

        let device_code = session.device_code.clone();

        // We only update the primary key value.
        // We don't need to update the index because the user_code and device_code don't change.
        self.set(&device_code, session, ttl).await.map_err(|e| {
            tracing::error!(error = %e, "failed to update device code");
            OpError::Storage
        })
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError> {
        self.delete(device_code).await.map_err(|e| {
            tracing::error!(error = %e, "failed to delete device code");
            OpError::Storage
        })
    }

    async fn consume_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        self.consume(device_code).await.map_err(|e| {
            tracing::error!(error = %e, "failed to consume device code");
            OpError::Storage
        })
    }
}
