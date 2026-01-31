# authly-flow

High-level authentication flows for [authly-rs](https://github.com/marcjazz/authly-rs).

This crate orchestrates authentication flows such as OAuth2, Device Flow, Client Credentials, and direct credentials-based auth, providing a high-level API that is independent of web frameworks.

## Features

- `OAuth2Flow`: Orchestrates the Authorization Code flow (initiation and finalization).
- `DeviceFlow`: Orchestrates the Device Authorization Flow (RFC 8628).
- `ClientCredentialsFlow`: Orchestrates the Client Credentials Flow (RFC 6749 Section 4.4).
- `CredentialsFlow`: Orchestrates direct credential-based authentication.
- Support for `UserMapper` to integrate with local user databases.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-flow = "0.1.0"
```

### Example: OAuth2 Flow

```rust
use authly_flow::OAuth2Flow;
use authly_providers_github::GitHubProvider;

// Setup provider and flow
let provider = GitHubProvider::new(client_id, client_secret, callback_url);
let flow = OAuth2Flow::new(provider);

// 1. Initiate login: Generate authorization URL and CSRF state
let (auth_url, csrf_state) = flow.initiate_login(&["user:email"], None);

// ... redirect user to auth_url, then receive code and state in callback ...

// 2. Finalize login: Exchange code for identity and tokens
let (identity, token, local_user) = flow.finalize_login(
    &code,
    &received_state,
    &expected_state,
    None // PKCE verifier
).await?;
```

### Example: Device Flow

```rust
use authly_flow::DeviceFlow;

let flow = DeviceFlow::new(client_id, device_auth_url, token_url);

// 1. Initiate device authorization
let resp = flow.initiate_device_authorization(&["read", "write"]).await?;

println!("Go to {} and enter code: {}", resp.verification_uri, resp.user_code);

// 2. Poll for token
let token = flow.poll_for_token(&resp.device_code, resp.interval).await?;
```

### Example: Client Credentials Flow

```rust
use authly_flow::ClientCredentialsFlow;

let flow = ClientCredentialsFlow::new(client_id, client_secret, token_url);

// Obtain an access token
let token = flow.get_token(Some(&["api:read"])).await?;
```

### Example: Credentials Flow

```rust
use authly_flow::CredentialsFlow;
// Assuming a provider that implements CredentialsProvider
let flow = CredentialsFlow::new(my_credentials_provider);

let (identity, local_user) = flow.authenticate(my_credentials).await?;
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcjazz/authly-rs) workspace.
