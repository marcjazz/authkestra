use crate::auth::state::Identity;

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
    /// Creates a new device code session with no poll recorded yet.
    ///
    /// this crate, but `DeviceCodeStore` implementations must be able to
    /// reconstruct a session from their own storage — this is the seam that
    /// makes that possible (authkestra#268). `last_polled_at` starts `None`
    /// and, since it's a `pub` field, can be set directly on the returned
    /// value.
    pub fn new(
        device_code: String,
        user_code: String,
        client_id: String,
        scope: String,
        expires_at: DateTime<Utc>,
        status: DeviceCodeStatus,
    ) -> Self {
        Self {
            device_code,
            user_code,
            client_id,
            scope,
            expires_at,
            status,
            last_polled_at: None,
        }
    }

    /// Checks if the device code session is expired.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now >= self.expires_at
    }
}
