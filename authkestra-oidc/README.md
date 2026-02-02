# authkestra-oidc

OpenID Connect (OIDC) implementation for [authkestra](https://github.com/marcjazz/authkestra).

This crate provides OIDC support for the `authkestra` framework, including automatic provider discovery, JWKS handling, and ID token validation. It implements the `OAuthProvider` trait from `authkestra-core`, making it easy to integrate any OIDC-compliant provider into your application.

## Features

- **OIDC Discovery**: Automatically fetch provider metadata from the issuer URL.
- **JWKS Handling**: Fetch and use JSON Web Key Sets for token signature verification.
- **ID Token Validation**: Securely decode and validate ID tokens, including issuer and audience checks.
- **PKCE Support**: Built-in support for Proof Key for Code Exchange (PKCE).
- **Identity Extraction**: Automatically maps OIDC claims (`sub`, `email`, `name`, `picture`) to the `authkestra` `Identity` struct.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
authkestra-oidc = "0.1.0"
authkestra-core = "0.1.0"
```

### Example

```rust
use authkestra_oidc::OidcProvider;
use authkestra_core::OAuthProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the provider using discovery
    let provider = OidcProvider::discover(
        "your_client_id".to_string(),
        "your_client_secret".to_string(),
        "http://localhost:8080/callback".to_string(),
        "https://accounts.google.com", // Issuer URL
    ).await?;

    // Generate an authorization URL
    let auth_url = provider.get_authorization_url(
        "random_state_string",
        &["email", "profile"],
        None // Optional PKCE code challenge
    );

    println!("Redirect user to: {}", auth_url);

    // After the user is redirected back with a code:
    // let (identity, token) = provider.exchange_code_for_identity("code_from_callback", None).await?;
    
    Ok(())
}
```

## Part of authkestra

This crate is part of the [authkestra](https://github.com/marcjazz/authkestra) workspace.
