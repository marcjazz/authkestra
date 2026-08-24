//! Integration tests for `ClientCredentialsFlow` (RFC 6749 Section 4.4).
//!
//! This flow had no test coverage at all prior to this change — unlike
//! `OAuth2Flow` (`oauth2_flow_tests.rs`) and `DeviceFlow`
//! (`device_flow_tests.rs`), which both already exercise the happy and
//! error paths of their token endpoints. Mirrors `device_flow_tests.rs`'s
//! approach: a real HTTP round trip against a `wiremock` server rather than
//! calling private internals, since `ClientCredentialsFlow` has no seams to
//! unit-test other than its one public `get_token` method.

use authkestra_engine::auth::AuthError;
use authkestra_engine::flow::ClientCredentialsFlow;
use serde_json::json;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn get_token_succeeds_and_parses_the_token_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=test_client"))
        // Assert the secret is actually sent. Without this, dropping
        // client_secret from the form entirely — i.e. sending unauthenticated
        // client_credentials requests — leaves every test in this file green.
        // Found by mutation-testing the suite during review of #232.
        .and(body_string_contains("client_secret=test_secret"))
        .and(body_string_contains("scope=read+write"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock_access_token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&mock_server)
        .await;

    let flow = ClientCredentialsFlow::new(
        "test_client".to_string(),
        "test_secret".to_string(),
        format!("{}/token", mock_server.uri()),
    );

    let token = flow.get_token(Some(&["read", "write"])).await.unwrap();

    assert_eq!(token.access_token, "mock_access_token");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.expires_in, Some(3600));
}

#[tokio::test]
async fn get_token_without_scopes_omits_the_scope_parameter() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_secret=test_secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "mock_access_token",
            "token_type": "Bearer"
        })))
        .mount(&mock_server)
        .await;

    let flow = ClientCredentialsFlow::new(
        "test_client".to_string(),
        "test_secret".to_string(),
        format!("{}/token", mock_server.uri()),
    );

    let token = flow.get_token(None).await.unwrap();
    assert_eq!(token.access_token, "mock_access_token");
}

#[tokio::test]
async fn get_token_surfaces_a_provider_error_on_non_success_response() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": "invalid_client",
            "error_description": "Client authentication failed"
        })))
        .mount(&mock_server)
        .await;

    let flow = ClientCredentialsFlow::new(
        "test_client".to_string(),
        "wrong_secret".to_string(),
        format!("{}/token", mock_server.uri()),
    );

    let err = flow.get_token(None).await.unwrap_err();
    match err {
        AuthError::Provider(msg) => assert!(
            msg.contains("invalid_client"),
            "expected the upstream error body to be surfaced, got: {msg}"
        ),
        other => panic!("expected AuthError::Provider, got {other:?}"),
    }
}
