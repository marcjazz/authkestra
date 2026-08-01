---
title: Passkeys (WebAuthn)
description: Learn how to implement phishing-resistant authentication using Passkeys in Authkestra.
---

Passkeys provide a highly secure, phishing-resistant alternative to passwords by utilizing public-key cryptography (WebAuthn). Authkestra supports Passkeys out of the box through the `WebAuthnAuthMethod` which is directly integrated into the `Engine` for seamless multi-factor and primary authentication flows.

## Enabling Passkeys

To use Passkeys, you must first enable the `webauthn` feature in your `Cargo.toml`:

```toml
[dependencies]
authkestra-engine = { version = "0.3", features = ["webauthn"] }
```

## Configuration

Authkestra uses `webauthn-rs` to power passkey support. You'll need to instantiate a `WebauthnBuilder`, configure your Relaying Party (RP) ID and Origin, and pass it into a `WebAuthnAuthMethod` instance when building your `Engine`.

```rust
use std::sync::Arc;
use webauthn_rs::prelude::WebauthnBuilder;
use url::Url;
use authkestra_engine::auth::webauthn::WebAuthnAuthMethod;
use authkestra_engine::engine::Engine;

let rp_id = "example.com";
let origin = Url::parse("https://example.com").unwrap();

let webauthn = WebauthnBuilder::new(rp_id, &origin)
    .unwrap()
    .rp_name("Authkestra Demo")
    .build()
    .unwrap();

// `my_store` implements the `CredentialStore` trait
let engine = Authkestra::builder()
    .with_webauthn(Arc::new(webauthn), my_store)
    .build();
```

## Authentication Ceremony

WebAuthn uses a two-step "ceremony":
1. **Start**: The server generates a cryptographic challenge and temporarily stores the session state.
2. **Finish**: The client (browser) signs the challenge with the authenticator and returns the signature to the server. The server verifies the signature and completes the authentication via the unified `Engine::authenticate` method.

### Starting Authentication
When the user wants to sign in, call `start_authentication`. You must pass the user's previously registered `Passkey` objects (retrieved from your credential store):

```rust
// `passkeys` is a `Vec<webauthn_rs::prelude::Passkey>` loaded from your store
let (challenge_response, auth_state) = engine.start_webauthn(&passkeys)?;
```
You return the `challenge_response` (which contains the `PublicKeyCredentialRequestOptions`) to the client so it can invoke `navigator.credentials.get()`. You must also temporarily store the `auth_state` (the internal session state) associated with this login attempt (e.g. in a session or Redis).

### Finishing Authentication
Once the client returns the signed assertion, pass it to the engine's `authenticate` method using the `AuthInput::WebAuthnAuthentication` variant. The engine expects the `auth_state_json` (the serialized internal session state created during `start_authentication`) to be provided.

```rust
use authkestra_engine::auth::{AuthInput, AuthResult};

let result = engine.authenticate(AuthInput::WebAuthnAuthentication {
    // The internal user ID you are trying to authenticate
    user_id: "user_123".to_string(),
    // `id` from the PublicKeyCredential response
    credential_id: "base64_url_credential_id".to_string(),
    // `response.clientDataJSON` from the PublicKeyCredential response, base64url-encoded
    client_data_json: "base64_url_client_data".to_string(),
    // `response.authenticatorData` from the PublicKeyCredential response, base64url-encoded
    authenticator_data: "base64_url_auth_data".to_string(),
    // `response.signature` from the PublicKeyCredential response, base64url-encoded
    signature: "base64_url_signature".to_string(),
    // `response.userHandle` from the PublicKeyCredential response, base64url-encoded (optional)
    user_handle: None, // Or Some("user_handle") if returned
    // The state string stored during `start_webauthn`, retrieved from your session/cache store
    auth_state_json: Some(auth_state_json_string),
}).await?;

match result {
    AuthResult::Success(identity) => {
        println!("Successfully authenticated as: {}", identity.external_id);
    }
    AuthResult::MfaRequired { mfa_token, allowed_methods, .. } => {
        // Handle step-up authentication if they need a second factor!
    }
}
```

Authkestra will perform rigorous cryptographic validation of the assertion against the stored public key, update the signature counter in the credential store to detect cloned authenticators, and return the authenticated `Identity` if successful!
