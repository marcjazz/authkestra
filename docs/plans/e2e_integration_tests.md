# Implementation Plan: E2E Integration Tests for Examples

## Goal Description
The objective is to create a robust, automated E2E testing suite that validates the `authkestra` examples actually work, boot up, and perform the OAuth flow and database interactions correctly. The tests will simulate external dependencies like GitHub/Google using `wiremock` and spin up actual databases like Redis using `testcontainers`.

## User Review Required
> [!IMPORTANT]
> **Cucumber vs. Standard Rust Tests**
> You asked if `cucumber` is the right solution. In the Rust ecosystem (and specifically for a developer-focused library like `authkestra`), **Cucumber adds significant boilerplate** (managing steps, World state, feature files) and is typically best when non-technical product owners need to read the tests.
> 
> **Recommendation:** We should use standard, idiomatic Rust integration tests (`tests/*.rs` with `#[tokio::test]`). This keeps the test suite in pure Rust, makes debugging much easier, and seamlessly integrates with `cargo test`. 
> 
> Do you agree to drop Cucumber in favor of standard `#[tokio::test]`?

## Proposed Changes

### Tests Infrastructure (`tests/` directory)
We will create a new integration test suite at the workspace level.

#### [NEW] `tests/examples_e2e.rs`
```rust
use wiremock::{MockServer, Mock, ResponseTemplate, matchers::{method, path}};
use testcontainers_modules::{redis::Redis, testcontainers::clients::Cli};
use std::process::Command;
use std::time::Duration;

#[tokio::test]
async fn test_axum_session_redis_example() {
    // 1. Setup Wiremock (Mock GitHub)
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/login/oauth/authorize"))
        .respond_with(ResponseTemplate::new(200).set_body_string("mock authorize page"))
        .mount(&mock_server)
        .await;
    // ... (Mock /access_token and /user)

    // 2. Setup Testcontainers (Real Redis)
    let docker = Cli::default();
    let redis_container = docker.run(Redis);
    let redis_url = format!("redis://127.0.0.1:{}", redis_container.get_host_port_ipv4(6379));

    // 3. Spawn the example as a child process
    let mut child = Command::new("cargo")
        .args(["run", "--example", "axum_session_redis"])
        .env("AUTHKESTRA_GITHUB_BASE_URL", mock_server.uri())
        .env("AUTHKESTRA_GITHUB_CLIENT_ID", "test_id")
        .env("AUTHKESTRA_GITHUB_CLIENT_SECRET", "test_secret")
        .env("REDIS_URL", redis_url)
        .spawn()
        .expect("Failed to start example");

    // Wait for server to boot
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 4. Drive the HTTP requests via reqwest
    let client = reqwest::Client::builder().cookie_store(true).build().unwrap();
    let resp = client.get("http://localhost:3000/auth/login/github").send().await.unwrap();
    
    // Assert we get redirected to the wiremock server
    assert!(resp.url().as_str().starts_with(&mock_server.uri()));

    // 5. Cleanup
    child.kill().expect("Failed to kill child process");
}
```

### Providers Mocking Support
To allow the examples to hit our `wiremock` server instead of the real GitHub/Google APIs during tests, we need a small tweak to the `GithubProvider` and `GoogleProvider` to respect an environment variable override.

#### [MODIFY] `crates/authkestra-providers/src/macros.rs`
```diff
         impl $provider_struct {
             pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
+                let base_url_env = format!("AUTHKESTRA_{}_BASE_URL", $provider_id.to_uppercase());
+                let api_url_env = format!("AUTHKESTRA_{}_API_URL", $provider_id.to_uppercase());
+
+                let auth_url = std::env::var(&base_url_env).map(|b| format!("{b}/login/oauth/authorize")).unwrap_or_else(|_| $default_auth_url.to_string());
+                let token_url = std::env::var(&base_url_env).map(|b| format!("{b}/login/oauth/access_token")).unwrap_or_else(|_| $default_token_url.to_string());
+                let user_url = std::env::var(&api_url_env).map(|b| format!("{b}/user")).unwrap_or_else(|_| $default_userinfo_url.to_string());
+
                 Self {
                     client_id,
                     client_secret,
                     redirect_uri,
                     http_client: reqwest::Client::builder()
                         .user_agent("authkestra")
                         .build()
                         .unwrap_or_else(|_| reqwest::Client::new()),
-                    authorization_url: $default_auth_url.to_string(),
-                    token_url: $default_token_url.to_string(),
-                    user_url: $default_userinfo_url.to_string(),
+                    authorization_url: auth_url,
+                    token_url: token_url,
+                    user_url: user_url,
                 }
             }
```

### CI Dependencies
#### [MODIFY] `Cargo.toml` (Workspace root)
We will add a root `tests/` directory and include the required dev-dependencies.
```toml
[dev-dependencies]
wiremock = "0.6"
testcontainers = "0.15"
testcontainers-modules = { version = "0.3", features = ["redis"] }
reqwest = { version = "0.12", features = ["cookies", "json"] }
tokio = { version = "1.0", features = ["full"] }
```

## Verification Plan

### Automated Tests
1. Run `cargo test --test examples_e2e` locally to verify the tests correctly spin up Redis, compile the examples, and execute the full OAuth flow against Wiremock.
2. Push to GitHub to ensure the `ci.yml` pipeline successfully executes the integration tests in the Ubuntu runner (which supports Docker/testcontainers by default).

### Manual Verification
No manual verification needed; the purpose of this change is strictly to automate example verification.
