use authkestra_engine::OAuthProvider;
use authkestra_oidc::provider::OidcProvider;
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_oidc_discover_and_auth_url() {
    let mock_server = MockServer::start().await;

    // Mock OIDC Discovery Endpoint
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": mock_server.uri(),
            "authorization_endpoint": format!("{}/authorize", mock_server.uri()),
            "token_endpoint": format!("{}/token", mock_server.uri()),
            "jwks_uri": format!("{}/jwks.json", mock_server.uri()),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })))
        .mount(&mock_server)
        .await;

    let provider = OidcProvider::discover(
        "test_client".to_string(),
        "test_secret".to_string(),
        "http://localhost/callback".to_string(),
        &mock_server.uri(),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();

    let url = provider.get_authorization_url("state_123", &["profile"], None, Some("nonce_123"));

    assert!(url.contains(&format!("{}/authorize", mock_server.uri())));
    assert!(url.contains("client_id=test_client"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("state=state_123"));
    assert!(url.contains("nonce=nonce_123"));
    assert!(url.contains("scope=profile%20openid") || url.contains("scope=openid%20profile"));
}

#[tokio::test]
async fn test_oidc_exchange_code() {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": mock_server.uri(),
            "authorization_endpoint": format!("{}/authorize", mock_server.uri()),
            "token_endpoint": format!("{}/token", mock_server.uri()),
            "jwks_uri": format!("{}/jwks.json", mock_server.uri()),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/jwks.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": [] // For this simple test, we mock a failure or empty JWKS if signature validation is strict, but let's see.
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "acc_tok",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": "id_tok_invalid_sig" // Will fail validation because of empty JWKS, but hits the code path!
        })))
        .mount(&mock_server)
        .await;

    let provider = OidcProvider::discover(
        "test_client".to_string(),
        "test_secret".to_string(),
        "http://localhost/callback".to_string(),
        &mock_server.uri(),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();

    let res = provider
        .exchange_code_for_identity("code123", None, None)
        .await;
    // It should fail to decode the JWT because the signature is invalid/missing,
    // but it exercises the exchange_code_for_identity fn!
    assert!(res.is_err());
}
