---
title: Device Signatures
description: How to implement device-bound signature authentication in Authkestra.
---

Authkestra supports device-bound signature authentication (proof-of-possession) through the `authkestra-devsig` crate. This allows you to cryptographically bind sessions or API requests to a specific hardware device, significantly reducing the risk of token theft.

## What are Device Signatures?

Unlike traditional bearer tokens (like a standard JWT or session cookie) which can be stolen and replayed by an attacker, device signatures require the client to prove possession of a private key for every request.

The server registers the public key (the "Device Identity") during enrollment. On subsequent requests, the client signs specific request parameters (like the URI, HTTP method, and a nonce) using their private key. The server verifies this signature using the enrolled public key.

## Prerequisites

Add the `authkestra-devsig` crate to your dependencies:

```toml
[dependencies]
authkestra-devsig = "0.1.0"
```

## How to use `authkestra-devsig`

The easiest way to use `authkestra-devsig` is via the official web framework integrations (`authkestra-axum` and `authkestra-actix`). These integrations provide ready-to-use middleware that intercepts requests, buffers the body to compute the required `bdh` (body digest hash), and verifies the signatures before your route handlers are ever executed.

### 1. Building the Verifier State

To start, construct the `DevSig` configuration state using the unified typestate builder. You will need a `VerifierConfig`, an `IssuerJwks` (a JWKS cache of the issuers trusted to mint attestations), and a `ReplayStore` (to protect against replay attacks).

```rust
use authkestra_devsig::{DevSig, VerifierConfig, IssuerJwks, replay::InMemoryReplayStore};
use std::sync::Arc;

let config = VerifierConfig {
    max_clock_skew_secs: 5,
    max_request_age_secs: 60,
    attestation_issuers: vec!["https://op.example.test".to_string()],
};

let jwks = IssuerJwks::new();
let replay_store = Arc::new(InMemoryReplayStore::new());

let devsig = DevSig::builder()
    .config(config)
    .jwks(jwks)
    .replay_store(replay_store)
    .build();
```

### 2. Wiring the Middleware (Axum)

In Axum, `authkestra-axum` provides the `DeviceSignatureLayer` middleware and an `AuthDeviceSignature` extractor.

```rust
use authkestra_axum::devsig::{DeviceSignatureLayer, AuthDeviceSignature};
use axum::{Router, routing::post, response::IntoResponse};

// Protect the route using the layer
let app: Router<()> = Router::new()
    .route("/v1/transfer", post(transfer_handler))
    .layer(DeviceSignatureLayer::from(devsig));

// The extractor reads the verified identity populated by the layer
async fn transfer_handler(AuthDeviceSignature(identity): AuthDeviceSignature) -> impl IntoResponse {
    format!("Verified request for subject: {}, device: {}", identity.subject, identity.device)
}
```

### 3. Wiring the Middleware (Actix)

In Actix, `authkestra-actix` provides the equivalent `DeviceSignatureAuth` middleware and `AuthDeviceSignature` extractor.

```rust
use authkestra_actix::devsig::{DeviceSignatureAuth, AuthDeviceSignature};
use actix_web::{App, HttpServer, post, Responder};

// The extractor reads the verified identity populated by the middleware
#[post("/v1/transfer")]
async fn transfer_handler(identity: AuthDeviceSignature) -> impl Responder {
    let AuthDeviceSignature(identity) = identity;
    format!("Verified request for subject: {}, device: {}", identity.subject, identity.device)
}

// Protect the route using the wrap() middleware
HttpServer::new(move || {
    let auth = DeviceSignatureAuth::from(devsig.clone());
    App::new().wrap(auth).service(transfer_handler)
})
```

By verifying the signature, you ensure that the request was genuinely initiated by the enrolled device, providing high-assurance authentication suitable for sensitive operations.
