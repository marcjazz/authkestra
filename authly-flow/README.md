# authly-flow

High-level authentication flows for [authly-rs](https://github.com/marcorichetta/authly-rs).

This crate orchestrates authentication flows such as OAuth2 and credentials-based auth, providing a high-level API that is independent of web frameworks.

## Features

- `OAuth2Flow`: Orchestrates the Authorization Code flow (initiation and finalization).
- `CredentialsFlow`: Orchestrates direct credential-based authentication.
- Support for `UserMapper` to integrate with local user databases.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authly-flow = "0.1.0"
```

### Example: OAuth2 Flow initiation

```rust
use authly_flow::OAuth2Flow;
use authly_providers_github::GitHubProvider;

// Setup provider and flow
let provider = GitHubProvider::new(client_id, client_secret, callback_url);
let flow = OAuth2Flow::new(provider);

// Generate authorization URL
let (auth_url, _csrf_state) = flow.initiate_auth(None);
```

## Part of authly-rs

This crate is part of the [authly-rs](https://github.com/marcorichetta/authly-rs) workspace.
