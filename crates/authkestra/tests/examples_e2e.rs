//! End-to-end smoke tests for the OAuth examples.
//!
//! Each test spawns a real example binary against a wiremock stand-in for the
//! upstream provider and asserts that `/auth/login/{provider}` redirects to it.
//! That is deliberately the *whole* assertion: it proves the example wires the
//! engine, the adapter routes and the provider together correctly, which is
//! what an example is documentation for.

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

/// Kills the spawned example on drop.
///
/// Without this, a failed assertion unwinds past the manual `kill()` and
/// leaves the example (and its `cargo run` parent) holding the port, which
/// then makes every subsequent run fail with `AddrInUse` for reasons that look
/// nothing like the original failure.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reserves a free port from the OS and releases it immediately.
///
/// There is an unavoidable race between releasing and the example binding, but
/// it is far smaller than the near-certainty of collision on a hardcoded 3000
/// when tests, other examples and stray processes all want the same port.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("failed to reserve a port")
        .local_addr()
        .expect("listener has no local address")
        .port()
}

async fn run_oauth_example(package: &str, example_bin: &str, provider: &str, login_path: &str) {
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

    let port = free_port();

    let child = Command::new("cargo")
        .args([
            "run",
            "-p",
            package,
            "--example",
            example_bin,
            "--all-features",
        ])
        .env(env_base_url, mock_server.uri())
        .env(env_api_url, mock_server.uri())
        .env(env_client_id, "test_id")
        .env(env_client_secret, "test_secret")
        // Every example reads `PORT`, so the harness never has to assume a
        // fixed port is free.
        .env("PORT", port.to_string())
        .spawn()
        .unwrap_or_else(|_| panic!("Failed to start {}", example_bin));
    let _guard = ChildGuard(child);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let url = format!("http://127.0.0.1:{port}{login_path}");
    let mut resp = None;
    for _ in 0..180 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Ok(r) = client.get(&url).send().await {
            resp = Some(r);
            break;
        }
    }

    let resp = resp.unwrap_or_else(|| panic!("{} failed to start after 180s", example_bin));

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

    // `_guard` kills the example here (and on any panic above).
}

#[tokio::test]
async fn test_all_oauth_examples_sequentially() {
    run_oauth_example(
        "authkestra",
        "axum_oauth2_github",
        "GITHUB",
        "/auth/login/github",
    )
    .await;
    run_oauth_example(
        "authkestra",
        "actix_oauth2_github",
        "GITHUB",
        "/auth/login/github",
    )
    .await;

    run_oauth_example(
        "authkestra",
        "axum_oidc_google",
        "GOOGLE",
        "/auth/login/google",
    )
    .await;
    run_oauth_example(
        "authkestra",
        "actix_oidc_google",
        "GOOGLE",
        "/auth/login/google",
    )
    .await;

    run_oauth_example(
        "authkestra",
        "axum_oauth_stateless",
        "GITHUB",
        "/auth/login/github",
    )
    .await;
    run_oauth_example(
        "authkestra",
        "actix_oauth_stateless",
        "GITHUB",
        "/auth/login/github",
    )
    .await;
}
