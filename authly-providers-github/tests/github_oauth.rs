use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, header, body_string_contains};
use authly_providers_github::GithubProvider;
use authly_core::{OAuthProvider, OAuthToken, Identity};

#[tokio::test]
async fn test_github_oauth_flow() {
    // Start a mock server
    let server = MockServer::start().await;

    // Mock the GitHub token endpoint
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .and(header("Accept", "application/json"))
        .and(body_string_contains("code=test_code"))
        .respond_with(ResponseTemplate::new(200)
            .append_header("content-type", "application/json")
            .set_body_json(serde_json::json!({
                "access_token": "test_access_token",
                "token_type": "bearer"
            })))
        .mount(&server)
        .await;

    // Mock the GitHub user info endpoint
    Mock::given(method("GET"))
        .and(path("/user"))
        .and(header("Authorization", "Bearer test_access_token"))
        .respond_with(ResponseTemplate::new(200)
            .append_header("content-type", "application/json")
            .set_body_json(serde_json::json!({
                "id": 123,
                "login": "test_user",
                "email": "test@example.com"
            })))
        .mount(&server)
        .await;

    let provider = GithubProvider::new(
        "test_client_id".to_string(),
        "test_client_secret".to_string(),
        format!("{}/callback", server.uri()),
    ).with_test_urls(
        format!("{}/login/oauth/authorize", server.uri()),
        format!("{}/login/oauth/access_token", server.uri()),
        format!("{}/user", server.uri()),
    );

    // Simulate the authorization URL generation
    let authorize_url = provider.get_authorization_url("test_state", &["user:email"], None);
    assert!(authorize_url.starts_with(&format!("{}/login/oauth/authorize", server.uri())));
    assert!(authorize_url.contains("state=test_state"));

    // In a real scenario, the user would be redirected to GitHub, authorize the app,
    // and then be redirected back to the callback URL with a code.
    // For testing, we'll directly use the mocked code.
    let code = "test_code";

    let (identity, token_response): (Identity, OAuthToken) = provider.exchange_code_for_identity(code, None).await.expect("Failed to exchange code");
    
    assert_eq!(token_response.access_token, "test_access_token");
    assert_eq!(identity.external_id, "123");
    assert_eq!(identity.username, Some("test_user".to_string()));
    assert_eq!(identity.email, Some("test@example.com".to_string()));
}
