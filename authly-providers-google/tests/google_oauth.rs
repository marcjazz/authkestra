use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, header, body_string_contains};
use authly_providers_google::GoogleProvider;
use authly_core::{OAuthProvider, OAuthToken, Identity};

#[tokio::test]
async fn test_google_oauth_flow() {
    // Start a mock server
    let server = MockServer::start().await;

    // Mock the Google token endpoint
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("code=test_code"))
        .respond_with(ResponseTemplate::new(200)
            .append_header("content-type", "application/json")
            .set_body_json(serde_json::json!({
                "access_token": "test_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test_refresh_token",
                "scope": "openid email profile",
                "id_token": "test_id_token"
            })))
        .mount(&server)
        .await;

    // Mock the Google user info endpoint
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .and(header("Authorization", "Bearer test_access_token"))
        .respond_with(ResponseTemplate::new(200)
            .append_header("content-type", "application/json")
            .set_body_json(serde_json::json!({
                "sub": "google-123",
                "email": "test@example.com",
                "name": "Test User",
                "picture": "https://example.com/picture.png",
                "email_verified": true,
                "locale": "en"
            })))
        .mount(&server)
        .await;

    let provider = GoogleProvider::new(
        "test_client_id".to_string(),
        "test_client_secret".to_string(),
        format!("{}/callback", server.uri()),
    ).with_test_urls(
        format!("{}/auth", server.uri()),
        format!("{}/token", server.uri()),
        format!("{}/userinfo", server.uri()),
        format!("{}/revoke", server.uri()),
    );

    // Simulate the authorization URL generation
    let authorize_url = provider.get_authorization_url("test_state", &["email", "profile"], None);
    assert!(authorize_url.starts_with(&format!("{}/auth", server.uri())));
    assert!(authorize_url.contains("state=test_state"));

    let code = "test_code";

    let (identity, token_response): (Identity, OAuthToken) = provider.exchange_code_for_identity(code, None).await.expect("Failed to exchange code");
    
    assert_eq!(token_response.access_token, "test_access_token");
    assert_eq!(token_response.refresh_token, Some("test_refresh_token".to_string()));
    
    assert_eq!(identity.external_id, "google-123");
    assert_eq!(identity.username, Some("Test User".to_string()));
    assert_eq!(identity.email, Some("test@example.com".to_string()));
    assert_eq!(identity.attributes.get("locale").map(|v| v.as_str()), Some("en"));
}
