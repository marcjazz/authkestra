use crate::device::{DeviceCodeStatus, DeviceCodeStore};
use crate::error::OpError;
use authkestra_engine::auth::state::Identity;
use serde::{Deserialize, Serialize};

/// Request payload for the device verification endpoint.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct DeviceVerifyRequest {
    /// The user code provided by the device.
    pub user_code: String,
    /// Whether the user approved or denied the request.
    pub approve: bool,
}

/// Response payload for a successful device verification request.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct DeviceVerifyResponse {
    /// Indicates whether the verification was processed successfully.
    pub success: bool,
}

/// Handles a device verification (user approval) request.
pub async fn handle_device_verify(
    req: DeviceVerifyRequest,
    identity: Identity,
    devices: &mut dyn DeviceCodeStore,
) -> Result<DeviceVerifyResponse, OpError> {
    let mut session = match devices.get_by_user_code(&req.user_code).await {
        Ok(Some(s)) => s,
        _ => return Err(OpError::InvalidCode),
    };

    match session.status {
        DeviceCodeStatus::Pending => {}
        _ => return Err(OpError::InvalidCode),
    }

    if req.approve {
        session.status = DeviceCodeStatus::Approved(identity);
    } else {
        session.status = DeviceCodeStatus::Denied;
    }

    devices.update_device_code(session).await?;

    Ok(DeviceVerifyResponse { success: true })
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::device::DeviceCodeSession;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_handle_device_verify_approve() {
        let mut devices = authkestra_engine::store::memory::MemoryStore::<
            crate::device::DeviceCodeSession,
        >::new();
        let session = DeviceCodeSession::new(
            "dev123".to_string(),
            "USER123".to_string(),
            "client1".to_string(),
            "openid".to_string(),
            Utc::now() + Duration::seconds(600),
            DeviceCodeStatus::Pending,
        );
        devices.store_device_code(session).await.unwrap();

        let identity = Identity {
            provider_id: "test".to_string(),
            external_id: "user1".to_string(),
            username: Some("user1".to_string()),
            email: None,
            attributes: HashMap::new(),
        };

        let req = DeviceVerifyRequest {
            user_code: "USER123".to_string(),
            approve: true,
        };

        let res = handle_device_verify(req, identity, &mut devices)
            .await
            .unwrap();
        assert!(res.success);

        let updated = devices.get_device_code("dev123").await.unwrap().unwrap();
        assert!(matches!(updated.status, DeviceCodeStatus::Approved(_)));
    }
}
