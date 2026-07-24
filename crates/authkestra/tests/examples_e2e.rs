use std::process::Command;
use std::time::Duration;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn test_axum_oauth2_github_example() {
    // 1. Setup Wiremock (Mock GitHub)
    let mock_server = MockServer::start().await;

    // Mock authorize endpoint
    Mock::given(method("GET"))
        .and(path("/login/oauth/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_string("mock authorize page"))
        .mount(&mock_server)
        .await;

    // Mock token endpoint
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_access_token",
            "token_type": "bearer"
        })))
        .mount(&mock_server)
        .await;

    // Mock user endpoint
    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 123456,
            "login": "mock_user",
            "email": "mock@example.com"
        })))
        .mount(&mock_server)
        .await;

    // 2. Spawn the example as a child process
    let mut child = Command::new("cargo")
        .args(["run", "--example", "axum_oauth2_github", "--features", "full"])
        .env("AUTHKESTRA_GITHUB_BASE_URL", mock_server.uri())
        .env("AUTHKESTRA_GITHUB_API_URL", mock_server.uri())
        .env("AUTHKESTRA_GITHUB_CLIENT_ID", "test_id")
        .env("AUTHKESTRA_GITHUB_CLIENT_SECRET", "test_secret")
        .spawn()
        .expect("Failed to start example");

    // Wait for server to boot with a polling loop (compilation can take time)
    let mut attempt = 0;
    let client = reqwest::Client::builder()
        // Do not automatically follow redirects so we can assert the Location header
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut resp = None;
    while attempt < 30 { // up to 30 seconds
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok(r) = client.get("http://127.0.0.1:3000/auth/login/github").send().await {
            resp = Some(r);
            break;
        }
        attempt += 1;
    }

    let resp = resp.expect("Failed to connect to the example server after 30 seconds. Is it running?");

    // Assert we get a 303 See Other (or 302) redirecting to wiremock
    assert!(
        resp.status().is_redirection(),
        "Expected redirection, got {}",
        resp.status()
    );
    
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with(&mock_server.uri()),
        "Expected redirect to wiremock, got: {}",
        location
    );

    // 4. Cleanup
    child.kill().expect("Failed to kill child process");
}
