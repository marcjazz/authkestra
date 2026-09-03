---
title: Client Credentials
description: Machine-to-machine authentication using the Client Credentials flow.
---

The **Client Credentials** grant type (defined in [RFC 6749 Section 4.4](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4)) is used for machine-to-machine authentication. Unlike standard OAuth flows, there is no interactive user involved. Instead, the application authenticates itself to the Identity Provider using its own Client ID and Client Secret to obtain an access token.

## Prerequisites

The Client Credentials flow is built natively into `authkestra-engine`. The snippet below uses the
engine's own types, so depend on it directly (the `authkestra` facade re-exports the same module as
`authkestra::core`, if you prefer a single dependency):

```toml
[dependencies]
authkestra-engine = "0.7"
tokio = { version = "1", features = ["full"] }
```

A runnable version lives in the repository — it needs no web framework at all:

```bash
cargo run -p authkestra-engine --example client_credentials
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

## `private_key_jwt` client authentication (RFC 7523)

Instead of sending a shared `client_secret`, a client can authenticate by signing a short-lived
JWT assertion with its own private key. `ClientCredentialsFlow::new_private_key_jwt` replaces
`new` for that:

```rust
use authkestra_engine::ClientCredentialsFlow;
use jsonwebtoken::{Algorithm, EncodingKey};

let flow = ClientCredentialsFlow::new_private_key_jwt(
    "your_client_id".to_string(),
    EncodingKey::from_ec_pem(private_key_pem)?,
    Algorithm::ES256,
    // Also becomes the `aud` claim of every assertion.
    "https://example.com/oauth/token".to_string(),
);
```

`alg` must agree with the key type the authorization server has registered for this client —
Authkestra's own OP derives the algorithm it accepts from the *registered public key*, never from
the assertion header. If the server holds several keys for the client, chain `.with_kid("k1")` so
it can tell which one signed. Everything after that is unchanged: call `get_token(...)` as above.

On the *server* side, accepting `private_key_jwt` requires wiring a `ClientAssertionStore` for
single-use `jti` tracking — see the [OP Server](/advanced/op-server/) page; the default refuses
every assertion.
