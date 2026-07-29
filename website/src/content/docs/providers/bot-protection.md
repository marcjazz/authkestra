---
title: Bot Protection (CAPTCHA)
description: Learn how to protect your authentication endpoints using CAPTCHA verification in Authkestra.
---

Authkestra provides built-in bot protection interceptors that validate CAPTCHA tokens during the authentication flow. This prevents automated credential stuffing and brute force attacks.

## Enabling Bot Protection

Enable the `captcha` feature in your `Cargo.toml`:

```toml
[dependencies]
authkestra-engine = { version = "0.2.0", features = ["captcha"] }
```

## Configuration

You can use either Cloudflare Turnstile (recommended) or Google reCAPTCHA. You provide the verification client (e.g., `TurnstileVerifier`) to the engine builder. 

```rust
use authkestra_engine::Authkestra;
use authkestra_engine::auth::captcha::TurnstileVerifier;

let turnstile = TurnstileVerifier::new("your_secret_key");

let engine = Authkestra::builder()
    .with_store(my_store)
    .with_captcha(turnstile) // Activates bot protection
    .build()
    .unwrap();
```

## How It Works

Once `with_captcha` is enabled, **every** call to `authenticate` that requires a CAPTCHA token must include it via the `captcha_token` field in the input.

```rust
use authkestra_engine::auth::AuthInput;

let identity = engine.authenticate(AuthInput::Password {
    username: "alice".to_string(),
    password: "Password123!".to_string(),
    captcha_token: Some("xxxx.token.xxxx".to_string()),
}).await?;
```

### Fail-Closed Design

Authkestra's bot protection is strictly **fail-closed**. This means if the CAPTCHA token is invalid, missing, or if the network request to the verification provider fails, the authentication is immediately rejected. It will never silently succeed and allow an attacker to bypass the protection!
