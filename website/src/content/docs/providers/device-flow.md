---
title: Device Flow
description: Authenticating input-constrained devices using OAuth 2.0 Device Authorization Grant.
---

The **Device Authorization Grant** (defined in [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)) is designed for devices that either lack a browser or have limited input capabilities (e.g., Smart TVs, CLI tools, IoT devices). 

Instead of authenticating directly on the device, the user is presented with a short code and a URL. They open the URL on a secondary device (like a smartphone or laptop), enter the code, and authenticate normally. Once completed, the primary device (which has been polling the server in the background) automatically receives its access token.

## Prerequisites

The Device Flow logic is built natively into the `authkestra-engine`. Ensure you have the crate installed:

```toml
[dependencies]
authkestra = { version = "0.2.4" }
```

## Using `DeviceFlow`

Authkestra provides the `DeviceFlow` struct which handles the two-step process: initiating the request and polling for completion.

```rust
use authkestra_engine::DeviceFlow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example: GitHub's Device Flow Endpoints
    let client_id = "your_client_id".to_string();
    let device_auth_url = "https://github.com/login/device/code".to_string();
    let token_url = "https://github.com/login/oauth/access_token".to_string();

    let flow = DeviceFlow::new(client_id, device_auth_url, token_url);

    // 1. Initiate Device Authorization
    let device_resp = flow
        .initiate_device_authorization(&["user", "repo"])
        .await?;

    println!("Open your browser and go to: {}", device_resp.verification_uri);
    println!("Enter the code: {}", device_resp.user_code);

    // Some providers return a complete URL that pre-fills the code
    if let Some(complete_uri) = &device_resp.verification_uri_complete {
        println!("Or click this direct link: {}", complete_uri);
    }

    println!("Waiting for authorization...");

    // 2. Poll the token endpoint
    // Authkestra automatically handles the polling interval and respects `authorization_pending` errors
    match flow.poll_for_token(&device_resp.device_code, device_resp.interval).await {
        Ok(token) => {
            println!("Authorization successful!");
            println!("Access Token: {}", token.access_token);
        }
        Err(e) => eprintln!("Authorization failed: {}", e),
    }

    Ok(())
}
```

## How Polling Works

Authkestra's `poll_for_token` automatically:
- Executes HTTP requests at the provider-requested `interval`.
- Intercepts `authorization_pending` and `slow_down` error responses without failing the future, dynamically adjusting the poll rate if the provider requests a slow down.
- Exits with an `expired_token` error if the user takes too long and the device code expires.
