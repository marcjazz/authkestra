# authkestra-devsig

Device-bound signature authentication for the `authkestra` framework: per-request proof of
possession of a device-bound private key, plus an Issuer-attested key binding, so that
verification needs no session store, no token introspection, and no per-request network call.

Proposed in [authkestra#137](https://github.com/marcjazz/authkestra/issues/137). See the crate
docs (`cargo doc -p authkestra-devsig --open`) for the full algorithm, the two credentials
(`X-Signature` and `X-Attestation`), and why the key-thumbprint binding check is the
security-critical step.

## Status

The verification core (`verify()`) is complete and covered by conformance tests. The `axum`
feature ships a `tower::Layer` + extractor as today's framework-integration surface; which
`authkestra-engine` trait (if any) this should eventually implement against is an open question
for the maintainer — see the crate-level docs on the `axum_integration` module and
authkestra#137.

## Usage

```rust,ignore
use authkestra_devsig::{IssuerJwks, InMemoryReplayStore, SignedRequest, VerifierConfig, verify};

let identity = verify(&request, &config, &jwks, &replay_store).await?;
```

With the `axum` feature enabled:

```rust,ignore
use authkestra_devsig::axum_integration::DeviceSignatureLayer;

let layer = DeviceSignatureLayer::new(config, jwks, replay_store);
let app = axum::Router::new().route("/v1/payments/transfer", post(handler)).layer(layer);
```
