---
title: Bot Protection (CAPTCHA)
description: Learn how to protect your authentication endpoints using CAPTCHA verification in Authkestra.
---

Authkestra provides built-in bot protection verifiers that validate CAPTCHA tokens. This prevents automated credential stuffing and brute force attacks on your authentication endpoints.

## Enabling Bot Protection

Enable the `captcha` feature in your `Cargo.toml`:

```toml
[dependencies]
authkestra-engine = { version = "0.2", features = ["captcha"] }
```

## Configuration

Authkestra supports Cloudflare Turnstile, hCaptcha, and Google reCAPTCHA out of the box via the `CaptchaVerifier` utility. You instantiate the verifier with your chosen provider and secret key.

```rust
use authkestra_engine::captcha::{CaptchaVerifier, CaptchaProvider};

// Example using Cloudflare Turnstile
let turnstile = CaptchaVerifier::new(CaptchaProvider::Turnstile, "your_secret_key");
```

## How It Works

Because bot protection occurs *before* standard authentication logic (like password hashing), you should manually invoke the verifier in your HTTP handlers prior to passing the credentials to Authkestra.

```rust
// Extract the captcha token from the user's login request
let token = req.captcha_token;
let remote_ip = req.remote_ip; // Optional, e.g. from X-Forwarded-For

// Validate the token against the provider API
match turnstile.verify(&token, remote_ip.as_deref()).await {
    Ok(true) => {
        // Success! Proceed with standard authentication
        // match engine.authenticate(...).await? {
        //     AuthResult::Success(identity) => ...
        //     AuthResult::MfaRequired { .. } => ...
        // }
    }
    Ok(false) | Err(_) => {
        // Bot detected or token invalid, reject the login request immediately!
        // return HTTP 403 Forbidden
    }
}
```

### Fail-Closed Design

Authkestra's bot protection is designed to be strictly **fail-closed**. This means if the CAPTCHA token is invalid, missing, or if the network request to the verification provider fails, the `verify` method returns an `Err`. It will never silently succeed and allow an attacker to bypass the protection!
