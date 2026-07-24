use std::process::Command;
use std::time::Duration;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn run_oauth_example(example_bin: &str, provider: &str, login_path: &str) {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/login/oauth/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_string("mock authorize page"))
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_access_token",
            "token_type": "bearer"
        })))
        .mount(&mock_server)
        .await;

    Mock::given(method("GET"))
        .and(path("/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 123456,
            "login": "mock_user",
            "email": "mock@example.com",
            "sub": "123456" // for google
        })))
        .mount(&mock_server)
        .await;

    let env_base_url = format!("AUTHKESTRA_{}_BASE_URL", provider);
    let env_api_url = format!("AUTHKESTRA_{}_API_URL", provider);
    let env_client_id = format!("AUTHKESTRA_{}_CLIENT_ID", provider);
    let env_client_secret = format!("AUTHKESTRA_{}_CLIENT_SECRET", provider);

    let mut child = Command::new("cargo")
        .args(["run", "--example", example_bin, "--features", "full"])
        .env(env_base_url, mock_server.uri())
        .env(env_api_url, mock_server.uri())
        .env(env_client_id, "test_id")
        .env(env_client_secret, "test_secret")
        .spawn()
        .expect(&format!("Failed to start {}", example_bin));

    let mut attempt = 0;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut resp = None;
    while attempt < 180 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let url = format!("http://127.0.0.1:3000{}", login_path);
        if let Ok(r) = client.get(&url).send().await {
            resp = Some(r);
            break;
        }
        attempt += 1;
    }

    let resp = resp.expect(&format!("{} failed to start after 180s", example_bin));

    assert!(
        resp.status().is_redirection(),
        "{} expected redirection, got {}",
        example_bin,
        resp.status()
    );

    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(
        location.starts_with(&mock_server.uri()),
        "{} expected redirect to wiremock, got: {}",
        example_bin,
        location
    );

    child.kill().expect("Failed to kill child process");

    // Give the OS a moment to release the port
    tokio::time::sleep(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn test_all_oauth_examples_sequentially() {
    run_oauth_example("axum_oauth2_github", "GITHUB", "/auth/login/github").await;
    run_oauth_example("actix_oauth2_github", "GITHUB", "/auth/login/github").await;

    run_oauth_example("axum_oidc_google", "GOOGLE", "/auth/login/google").await;
    run_oauth_example("actix_oidc_google", "GOOGLE", "/auth/login/google").await;

    run_oauth_example("axum_oauth_stateless", "GITHUB", "/auth/github").await;
    run_oauth_example("actix_oauth_stateless", "GITHUB", "/auth/github").await;
}
