---
title: Client Credentials
description: Machine-to-machine authentication using the Client Credentials flow.
---

The **Client Credentials** grant type (defined in [RFC 6749 Section 4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)) is used for machine-to-machine authentication. Unlike standard OAuth flows, there is no interactive user involved. Instead, the application authenticates itself to the Identity Provider using its own Client ID and Client Secret to obtain an access token.

## Prerequisites

The Client Credentials flow is built natively into the `authkestra-engine`. If you are using the `authkestra` facade crate, ensure you have enabled the framework.

```toml
[dependencies]
authkestra = { version = "0.2" }
```

## Using `ClientCredentialsFlow`

Authkestra provides a dedicated `ClientCredentialsFlow` struct to handle the token exchange securely.

```rust
use authkestra_engine::ClientCredentialsFlow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client_id = "your_client_id".to_string();
    let client_secret = "your_client_secret".to_string();
    let token_url = "https://example.com/oauth/token".to_string();

    // 1. Initialize the Flow
    let flow = ClientCredentialsFlow::new(client_id, client_secret, token_url);

    // 2. Request a token (with optional scopes)
    let scopes = ["api:read", "api:write"];
    
    match flow.get_token(Some(&scopes)).await {
        Ok(token) => {
            println!("Successfully obtained access token!");
            println!("Access Token: {}", token.access_token);
            
            if let Some(expires_in) = token.expires_in {
                println!("Expires in: {} seconds", expires_in);
            }
        }
        Err(e) => {
            eprintln!("Failed to obtain access token: {}", e);
        }
    }

    Ok(())
}
```

## When to use this flow

You should use the Client Credentials flow when:
1. You are building a backend daemon, cron job, or microservice.
2. The application needs to interact with an API on its *own* behalf, rather than on behalf of a specific user.
3. The credentials (Client ID and Secret) can be stored securely (e.g., in a secret manager or environment variables) away from public access.
