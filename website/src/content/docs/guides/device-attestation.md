---
title: Device Attestation
description: Step-by-step walkthrough of enrolling a device key and re-issuing its attestation against a running authkestra-op server.
---

This guide walks through the **device/service attestation** ceremony end to end: generating a keypair, enrolling it against an `authkestra-op` server, receiving a short-lived attestation, and silently renewing it before it expires. It narrates exactly what the two runnable examples in the repository do — [`crates/authkestra/examples/axum_op_server_attestation.rs`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples/axum_op_server_attestation.rs) and [`crates/authkestra/examples/actix_op_server_attestation.rs`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples/actix_op_server_attestation.rs) — so you can follow along and then adapt the same steps into your own mobile client or backend service.

This is the how-to companion to the [Device/Service Attestation Issuance](/advanced/op-server/#deviceservice-attestation-issuance) reference, which covers the API shape (`AttestationConfig`, `SecondFactorVerifier`, wiring) in more depth. If you're implementing the *verifying* side of a request signed with one of these attestations, see the `authkestra-devsig` section of the adapters chapter instead — this guide only covers issuance.

## Prerequisites

You need a running `authkestra-op` instance with the attestation router wired in (`op_axum_attestation_router()` / `op_actix_scope()`), as described in the reference doc. For this guide, we'll run the example server, which needs no external services — its `EnrolmentChallengeStore` is an in-memory `MemoryStore`:

```sh
# Axum
cargo run -p authkestra --example axum_op_server_attestation --features full

# Actix
cargo run -p authkestra --example actix_op_server_attestation --features full
```

Both examples start a real server and then immediately play the client side of the ceremony against it — enrolling a device key and re-issuing its attestation — so running either one shows you the whole flow below happening live, with logging.

## Step 1: Generate a device keypair

The device (or service) generates an EC P-256 keypair locally — in production this lives in hardware-backed storage (Secure Enclave on iOS, StrongBox/Keystore on Android). The private key never leaves the device; only the public key, as a JWK, is sent to the server:

```rust
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::{JwkEcKey, PublicKey};
use rand_core::OsRng;

let signing_key = SigningKey::random(&mut OsRng);
let public_key: PublicKey<p256::NistP256> = signing_key.verifying_key().into();
let public_jwk = serde_json::to_value(&JwkEcKey::from(&public_key))?;
```

## Step 2: Enrol the key (`POST /enrol`)

Submit the public JWK together with an identity to bind it to and a second-factor proof. `authkestra-op` doesn't interpret the second factor itself — it hands it to whatever `SecondFactorVerifier` the server configured (SMS/TOTP for a device, an out-of-band approval or bootstrap secret for a service):

```rust
let enrol_body = serde_json::json!({
    "subject": "user-42",
    "principal_id": "device-abc123",
    "principal_type": "device",
    "public_jwk": public_jwk,
    "attributes": { "kyc_level": "verified" },
    "second_factor": { "kind": "demo_otp", "value": "123456" },
});

let challenge: serde_json::Value = client
    .post(format!("{base}/enrol"))
    .json(&enrol_body)
    .send().await?
    .json().await?;

let challenge_value = challenge["challenge"].as_str().unwrap();
```

If the second factor checks out, the server responds with a single-use, short-lived `challenge` string — a proof-of-possession nonce, not a session. Nothing is bound to the key yet; that happens in the next step.

## Step 3: Complete the challenge (`POST /enrol/complete`)

Sign the challenge with the same private key you generated in Step 1 (a compact JWS over `{"challenge": ...}`, `ES256`), then submit the challenge and its signature:

```rust
use jsonwebtoken::{Algorithm, EncodingKey, Header};

let encoding_key = EncodingKey::from_ec_der(&pkcs8_der);
let challenge_signature = jsonwebtoken::encode(
    &Header::new(Algorithm::ES256),
    &serde_json::json!({ "challenge": challenge_value }),
    &encoding_key,
)?;

let attestation: serde_json::Value = client
    .post(format!("{base}/enrol/complete"))
    .json(&serde_json::json!({
        "challenge": challenge_value,
        "challenge_signature": challenge_signature,
    }))
    .send().await?
    .json().await?;
```

The server consumes the challenge (it cannot be replayed), verifies the signature was produced by the *enrolled* key, computes `cnf.jkt` from that key — never from anything the client claims — and mints the attestation. The response carries the attestation itself plus its lifetime:

```json
{
  "attestation": "eyJhbGciOi...",
  "expires_in": 86400,
  "reissue_after": 43200
}
```

At this point enrolment is done: `attestation` is a JWS whose `cnf.jkt` claim is bound to the key you generated in Step 1. A verifier that trusts this OP's JWKS can confirm that binding — but the attestation is not itself a bearer credential; using it to authenticate a request also requires a per-request signature over that request, which is what `authkestra-devsig` verifies on the resource-server side.

## Step 4: Re-issue before expiry (`POST /reissue`)

Well before `reissue_after` seconds have elapsed, silently renew the attestation by proving possession of the same key again — no second factor required this time, since continuity of the key is what stands in for it:

```rust
let reissue_body = serde_json::json!({
    "attestation": attestation["attestation"],
    "public_jwk": public_jwk,
});

let reissue_challenge: serde_json::Value = client
    .post(format!("{base}/reissue"))
    .json(&reissue_body)
    .send().await?
    .json().await?;
```

`/reissue` returns a fresh challenge, exactly like `/enrol` did. Sign it and complete it through `/enrol/complete` again — the same call as Step 3 — and you get back a renewed attestation with a new expiry:

```rust
let reissue_challenge_value = reissue_challenge["challenge"].as_str().unwrap();
// sign + POST /enrol/complete again, same as Step 3
```

If the server has an `AttestationStatusProvider` configured, re-issuance is also where it gets a chance to refuse a revoked principal outright, or refresh the attestation's attributes (e.g. an updated `kyc_level`) — see that trait's docs in the reference page. Without one configured, re-issuance just copies the previous attributes forward.

## Putting it together

Both example files run this entire sequence — enrolment followed by one re-issuance — against a real in-process server, printing each step's response as it goes. They're the best place to see the full, working request/response cycle in one place, and a reasonable starting point to copy from when wiring up your own mobile client or backend service:

- [`crates/authkestra/examples/axum_op_server_attestation.rs`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples/axum_op_server_attestation.rs)
- [`crates/authkestra/examples/actix_op_server_attestation.rs`](https://github.com/marcjazz/authkestra/tree/main/crates/authkestra/examples/actix_op_server_attestation.rs)
