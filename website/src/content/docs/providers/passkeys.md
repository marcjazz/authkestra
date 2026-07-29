---
title: Passkeys (WebAuthn)
description: Learn how to implement phishing-resistant authentication using Passkeys in Authkestra.
---

Passkeys provide a highly secure, phishing-resistant alternative to passwords by utilizing public-key cryptography (WebAuthn). Authkestra supports Passkeys out of the box.

## Enabling Passkeys

To use Passkeys, you must first enable the `webauthn` feature in your `Cargo.toml`:

```toml
[dependencies]
authkestra-engine = { version = "0.2.0", features = ["webauthn"] }
```

## Configuration

Authkestra uses `webauthn-rs` to power passkey support. You'll need to instantiate a `WebauthnBuilder`, configure your Relaying Party (RP) ID and Origin, and pass it into the `Authkestra` engine via the builder pattern.

```rust
use webauthn_rs::prelude::WebauthnBuilder;
use url::Url;
use authkestra_engine::Authkestra;

let rp_id = "example.com";
let origin = Url::parse("https://example.com").unwrap();

let webauthn = WebauthnBuilder::new(rp_id, &origin)
    .unwrap()
    .rp_name("Authkestra Demo")
    .build()
    .unwrap();

let engine = Authkestra::builder()
    .with_store(my_store)
    .with_webauthn(webauthn) // Enables the passkeys flow
    .build()
    .unwrap();
```

## Authentication Ceremony

WebAuthn uses a two-step "ceremony":
1. **Start**: The server generates a cryptographic challenge and temporarily stores the session state.
2. **Finish**: The client (browser) signs the challenge with the authenticator and returns the signature to the server. The server verifies the signature and completes the authentication.

### Starting Authentication
When the user wants to sign in, call `start_authentication`:

```rust
use authkestra_engine::auth::{AuthMethod, AuthInput};

let challenge_response = engine.start_authentication(AuthInput::WebauthnStart {
    user_id: "user_123".to_string(),
}).await?;
```
You return the `challenge_response` (which contains the `PublicKeyCredentialRequestOptions`) to the client so it can invoke `navigator.credentials.get()`.

### Finishing Authentication
Once the client returns the signed assertion, pass it to `finish_authentication`. The engine expects the `auth_state` (the internal session state created during `start_authentication`) to be provided as JSON.

```rust
let identity = engine.authenticate(AuthInput::WebauthnFinish {
    user_id: "user_123".to_string(),
    auth_response: client_assertion_json, // From the browser
    auth_state: state_json, // From your session store
}).await?;
```

Authkestra will perform rigorous cryptographic validation of the assertion against the stored public key, update the signature counter to detect cloned authenticators, and return the authenticated `Identity` if successful!
