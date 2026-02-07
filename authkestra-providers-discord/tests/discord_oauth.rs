use authkestra_core::{Identity, OAuthProvider, OAuthToken};
use authkestra_providers_discord::DiscordProvider;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_discord_oauth_flow() {
    // Start a mock server
    let server = MockServer::start().await;

    // Mock the Discord token endpoint
    Mock::given(method("POST"))
        .and(path("/api/oauth2/token"))
        .and(body_string_contains("code=test_code"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "access_token": "test_access_token",
                    "token_type": "Bearer",
                    "expires_in": 604800,
                    "refresh_token": "test_refresh_token",
                    "scope": "identify email"
                })),
        )
        .mount(&server)
        .await;

    // Mock the Discord user info endpoint
    Mock::given(method("GET"))
        .and(path("/api/users/@me"))
        .and(header("Authorization", "Bearer test_access_token"))
        .respond_with(
            ResponseTemplate::new(200)
                .append_header("content-type", "application/json")
                .set_body_json(serde_json::json!({
                    "id": "123456789",
                    "username": "testuser",
                    "discriminator": "0001",
                    "email": "test@example.com",
                    "verified": true
                })),
        )
        .mount(&server)
        .await;

    let provider = DiscordProvider::new(
        "test_client_id".to_string(),
        "test_client_secret".to_string(),
        format!("{}/callback", server.uri()),
    )
    .with_test_urls(
        format!("{}/api/oauth2/token", server.uri()),
        format!("{}/api/users/@me", server.uri()),
        format!("{}/api/oauth2/token/revoke", server.uri()),
    );

    // Simulate the authorization URL generation
    let authorize_url = provider.get_authorization_url("test_state", &["identify", "email"], None);
    assert!(authorize_url.contains("state=test_state"));
    assert!(authorize_url.contains("client_id=test_client_id"));

    let code = "test_code";

    let (identity, token_response): (Identity, OAuthToken) = provider
        .exchange_code_for_identity(code, None)
        .await
        .expect("Failed to exchange code");

    assert_eq!(token_response.access_token, "test_access_token".to_string());
    assert_eq!(
        token_response.refresh_token,
        Some("test_refresh_token".to_string())
    );

    assert_eq!(identity.external_id, "123456789");
    assert_eq!(identity.username, Some("testuser#0001".to_string()));
    assert_eq!(identity.email, Some("test@example.com".to_string()));
}
