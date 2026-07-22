use super::*;
use crate::client::{ClientRegistration, GrantType, InMemoryClientStore};
use crate::code::InMemoryAuthorizationCodeStore;
use crate::device::{DeviceCodeSession, DeviceCodeStatus, InMemoryDeviceCodeStore};
use crate::handlers::token::tests::{test_config, test_tokens};
use crate::refresh::InMemoryRefreshTokenStore;
use authkestra_engine::auth::state::Identity;
use chrono::{Duration, Utc};
use std::collections::HashMap;

fn default_device_req(device_code: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        code: None,
        redirect_uri: None,
        client_id: Some("client1".to_string()),
        client_secret: None,
        code_verifier: None,
        scope: None,
        refresh_token: None,
        device_code: Some(device_code.to_string()),
        subject_token: None,
        subject_token_type: None,
        actor_token: None,
        actor_token_type: None,
        requested_token_type: None,
        audience: None,
    }
}

fn test_identity() -> Identity {
    Identity {
        provider_id: "test".to_string(),
        external_id: "user1".to_string(),
        username: Some("user1".to_string()),
        email: None,
        attributes: HashMap::new(),
    }
}

async fn setup_store(
    status: DeviceCodeStatus,
    client_id: &str,
    scope: &str,
) -> (InMemoryDeviceCodeStore, InMemoryClientStore) {
    let devices = InMemoryDeviceCodeStore::new();
    let session = DeviceCodeSession {
        device_code: "dev123".to_string(),
        user_code: "USER123".to_string(),
        client_id: client_id.to_string(),
        scope: scope.to_string(),
        expires_at: Utc::now() + Duration::seconds(600),
        status,
        last_polled_at: None,
    };
    devices.store_device_code(session).await.unwrap();

    let clients = InMemoryClientStore::new();
    clients.register(ClientRegistration {
        client_id: "client1".to_string(),
        client_secret_hash: None,
        redirect_uris: vec![],
        grant_types: vec![GrantType::DeviceCode],
        scopes: vec![],
        require_pkce: false,
        allowed_audiences: vec![],
    });

    (devices, clients)
}

#[tokio::test]
async fn test_device_denied() {
    let (devices, clients) = setup_store(DeviceCodeStatus::Denied, "client1", "openid").await;
    let req = default_device_req("dev123");

    let res = handle_token(
        req,
        None,
        &test_config(false),
        &clients,
        &InMemoryAuthorizationCodeStore::new(),
        &InMemoryRefreshTokenStore::new(),
        &devices,
        &test_tokens(),
    )
    .await;

    assert!(res.is_err());
    assert_eq!(res.unwrap_err().error, "access_denied");
}

#[tokio::test]
async fn test_device_wrong_client() {
    let (devices, clients) = setup_store(
        DeviceCodeStatus::Approved(test_identity()),
        "client2",
        "openid",
    )
    .await;
    let req = default_device_req("dev123"); // requests with client1

    let res = handle_token(
        req,
        None,
        &test_config(false),
        &clients,
        &InMemoryAuthorizationCodeStore::new(),
        &InMemoryRefreshTokenStore::new(),
        &devices,
        &test_tokens(),
    )
    .await;

    assert!(res.is_err());
    assert_eq!(res.unwrap_err().error, "invalid_grant");
}

#[tokio::test]
async fn test_device_expired() {
    let devices = InMemoryDeviceCodeStore::new();
    let session = DeviceCodeSession {
        device_code: "dev123".to_string(),
        user_code: "USER123".to_string(),
        client_id: "client1".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() - Duration::seconds(600), // Expired
        status: DeviceCodeStatus::Approved(test_identity()),
        last_polled_at: None,
    };
    devices.store_device_code(session).await.unwrap();

    let clients = InMemoryClientStore::new();
    clients.register(ClientRegistration {
        client_id: "client1".to_string(),
        client_secret_hash: None,
        redirect_uris: vec![],
        grant_types: vec![GrantType::DeviceCode],
        scopes: vec![],
        require_pkce: false,
        allowed_audiences: vec![],
    });

    let req = default_device_req("dev123");

    let res = handle_token(
        req,
        None,
        &test_config(false),
        &clients,
        &InMemoryAuthorizationCodeStore::new(),
        &InMemoryRefreshTokenStore::new(),
        &devices,
        &test_tokens(),
    )
    .await;

    assert!(res.is_err());
    assert_eq!(res.unwrap_err().error, "expired_token");
}

#[tokio::test]
async fn test_device_offline_access() {
    let (devices, clients) = setup_store(
        DeviceCodeStatus::Approved(test_identity()),
        "client1",
        "openid offline_access",
    )
    .await;
    let req = default_device_req("dev123");

    let res = handle_token(
        req,
        None,
        &test_config(false),
        &clients,
        &InMemoryAuthorizationCodeStore::new(),
        &InMemoryRefreshTokenStore::new(),
        &devices,
        &test_tokens(),
    )
    .await;

    assert!(res.is_ok());
    let res = res.unwrap();
    assert!(res.refresh_token.is_some());
}

#[tokio::test]
async fn test_device_concurrency() {
    let devices = std::sync::Arc::new(InMemoryDeviceCodeStore::new());
    let session = DeviceCodeSession {
        device_code: "dev123".to_string(),
        user_code: "USER123".to_string(),
        client_id: "client1".to_string(),
        scope: "openid".to_string(),
        expires_at: Utc::now() + Duration::seconds(600),
        status: DeviceCodeStatus::Approved(test_identity()),
        last_polled_at: None,
    };
    devices.store_device_code(session).await.unwrap();

    let clients = std::sync::Arc::new(InMemoryClientStore::new());
    clients.register(ClientRegistration {
        client_id: "client1".to_string(),
        client_secret_hash: None,
        redirect_uris: vec![],
        grant_types: vec![GrantType::DeviceCode],
        scopes: vec![],
        require_pkce: false,
        allowed_audiences: vec![],
    });

    let config = std::sync::Arc::new(test_config(false));
    let tokens = std::sync::Arc::new(test_tokens());

    let mut handles = vec![];

    for _ in 0..10 {
        let devices = devices.clone();
        let clients = clients.clone();
        let config = config.clone();
        let tokens = tokens.clone();

        handles.push(tokio::spawn(async move {
            let req = default_device_req("dev123");
            handle_token(
                req,
                None,
                &config,
                &*clients,
                &InMemoryAuthorizationCodeStore::new(),
                &InMemoryRefreshTokenStore::new(),
                &*devices,
                &*tokens,
            )
            .await
        }));
    }

    let mut successes = 0;
    let mut invalid_grants = 0;

    for handle in handles {
        match handle.await.unwrap() {
            Ok(_) => successes += 1,
            Err(e) if e.error == "invalid_grant" => invalid_grants += 1,
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    assert_eq!(successes, 1, "Exactly one request should succeed");
    assert_eq!(
        invalid_grants, 9,
        "All other requests should fail with invalid_grant"
    );
}
