use crate::error::OpError;
use async_trait::async_trait;
use authkestra_engine::auth::state::Identity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

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

/// An in-memory implementation of `DeviceCodeStore` for testing and development.
#[derive(Default)]
pub struct InMemoryDeviceCodeStore {
    sessions: RwLock<HashMap<String, DeviceCodeSession>>,
}

impl InMemoryDeviceCodeStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl DeviceCodeStore for InMemoryDeviceCodeStore {
    async fn store_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        self.sessions
            .write()
            .unwrap()
            .insert(session.device_code.clone(), session);
        Ok(())
    }

    async fn get_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        Ok(self.sessions.read().unwrap().get(device_code).cloned())
    }

    async fn get_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        let sessions = self.sessions.read().unwrap();
        Ok(sessions
            .values()
            .find(|s| s.user_code == user_code)
            .cloned())
    }

    async fn update_device_code(&self, session: DeviceCodeSession) -> Result<(), OpError> {
        let mut sessions = self.sessions.write().unwrap();
        if sessions.contains_key(&session.device_code) {
            sessions.insert(session.device_code.clone(), session);
        }
        Ok(())
    }

    async fn delete_device_code(&self, device_code: &str) -> Result<(), OpError> {
        self.sessions.write().unwrap().remove(device_code);
        Ok(())
    }

    async fn consume_device_code(
        &self,
        device_code: &str,
    ) -> Result<Option<DeviceCodeSession>, OpError> {
        Ok(self.sessions.write().unwrap().remove(device_code))
    }
}
