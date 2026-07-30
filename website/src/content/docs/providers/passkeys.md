---
title: Passkeys (WebAuthn)
description: Learn how to implement phishing-resistant authentication using Passkeys in Authkestra.
---

Passkeys provide a highly secure, phishing-resistant alternative to passwords by utilizing public-key cryptography (WebAuthn). Authkestra supports Passkeys out of the box through the `WebAuthnAuthMethod`.

## Enabling Passkeys

To use Passkeys, you must first enable the `webauthn` feature in your `Cargo.toml`:

```toml
[dependencies]
authkestra-engine = { version = "0.2.0", features = ["webauthn"] }
```

## Configuration

Authkestra uses `webauthn-rs` to power passkey support. You'll need to instantiate a `WebauthnBuilder`, configure your Relaying Party (RP) ID and Origin, and pass it into a `WebAuthnAuthMethod` instance along with your credential store.

```rust
use std::sync::Arc;
use webauthn_rs::prelude::WebauthnBuilder;
use url::Url;
use authkestra_engine::auth::webauthn::WebAuthnAuthMethod;

let rp_id = "example.com";
let origin = Url::parse("https://example.com").unwrap();

let webauthn = WebauthnBuilder::new(rp_id, &origin)
    .unwrap()
    .rp_name("Authkestra Demo")
    .build()
    .unwrap();

// `my_store` implements the `CredentialStore` trait
let passkeys_method = WebAuthnAuthMethod::new(Arc::new(webauthn), my_store);
```

## Authentication Ceremony

WebAuthn uses a two-step "ceremony":
1. **Start**: The server generates a cryptographic challenge and temporarily stores the session state.
2. **Finish**: The client (browser) signs the challenge with the authenticator and returns the signature to the server. The server verifies the signature and completes the authentication.

### Starting Authentication
When the user wants to sign in, call `start_authentication`. You must pass the user's previously registered `Passkey` objects (retrieved from your credential store):

```rust
// `passkeys` is a `Vec<webauthn_rs::prelude::Passkey>` loaded from your store
let (challenge_response, auth_state) = passkeys_method.start_authentication(&passkeys)?;
```
You return the `challenge_response` (which contains the `PublicKeyCredentialRequestOptions`) to the client so it can invoke `navigator.credentials.get()`. You must also temporarily store the `auth_state` (the internal session state) associated with this login attempt (e.g. in a session or Redis).

### Finishing Authentication
Once the client returns the signed assertion, pass it to `authenticate` using the `AuthInput::WebAuthnAuthentication` variant. The engine expects the `auth_state_json` (the serialized internal session state created during `start_authentication`) to be provided.

```rust
use authkestra_engine::auth::{AuthInput, AuthMethod};

let identity = passkeys_method.authenticate(AuthInput::WebAuthnAuthentication {
    user_id: "user_123".to_string(),
    credential_id: "base64_url_credential_id".to_string(),
    client_data_json: "base64_url_client_data".to_string(),
    authenticator_data: "base64_url_auth_data".to_string(),
    signature: "base64_url_signature".to_string(),
    user_handle: None, // Or Some("user_handle") if returned
    auth_state_json: Some(auth_state_json_string), // Retrieved from your session store
}).await?;
```

Authkestra will perform rigorous cryptographic validation of the assertion against the stored public key, update the signature counter in the credential store to detect cloned authenticators, and return the authenticated `Identity` if successful!
