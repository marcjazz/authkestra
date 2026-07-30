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

`authkestra-devsig` provides robust validation for JSON Web Signatures (JWS), Replay protection, and structured Attestation parsing.

The primary entrypoint for verifying signatures is the validation module. You construct an expected request representation and verify the incoming JWS token against it.

### Enrollment (Attestation)

During device enrollment, the client generates a keypair and sends the public key (often wrapped in an attestation statement to prove it was generated in secure hardware, like a TPM or Secure Enclave) to the server.

```rust
use authkestra_devsig::attestation::verify_attestation;

// ... Inside your enrollment handler ...
// Verify the attestation statement sent by the device
// This ensures the key is hardware-bound and extractable
let device_identity = verify_attestation(attestation_payload, expected_challenge)?;

// Save device_identity.public_key() to your database alongside the User ID.
```

### Verification (Proof of Possession)

For ongoing API requests, the client signs the request parameters. 

```rust
use authkestra_devsig::signature::verify_request_signature;
use authkestra_devsig::request::RequestData;

// Reconstruct the request data that the client supposedly signed
let req_data = RequestData {
    method: "POST".to_string(),
    uri: "/api/transfer".to_string(),
    body_hash: computed_sha256,
};

// Retrieve the public key associated with this device/user from your DB
let public_key = get_public_key_from_db(device_id).await?;

// Verify the incoming JWS header/signature against the request data
let is_valid = verify_request_signature(
    &incoming_jws, 
    &req_data, 
    &public_key
)?;

if !is_valid {
    return Err(AuthError::InvalidSignature);
}
```

By verifying the signature, you ensure that the request was genuinely initiated by the enrolled device, providing high-assurance authentication suitable for sensitive operations.
