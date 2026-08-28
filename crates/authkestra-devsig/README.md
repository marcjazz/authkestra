# authkestra-devsig

Device-bound signature authentication for the `authkestra` framework: per-request proof of
possession of a device-bound private key, plus an Issuer-attested key binding, so that
verification needs no session store, no token introspection, and no per-request network call.

Proposed in [authkestra#137](https://github.com/marcjazz/authkestra/issues/137). See the crate
docs (`cargo doc -p authkestra-devsig --open`) for the full algorithm, the two credentials
(`X-Signature` and `X-Attestation`), and why the key-thumbprint binding check is the
security-critical step.

## Status

The verification core (`verify()`) is complete and covered by conformance tests. This crate is
deliberately framework-agnostic (per the workspace `AGENTS.md`'s "Framework Agnostic" rule) —
it does not depend on axum, actix, or any other web framework. Which `authkestra-engine` trait
(if any) framework integrations should eventually implement against is an open question for the
maintainer — see authkestra#137.

## Usage

```rust,ignore
use authkestra_devsig::{IssuerJwks, InMemoryReplayStore, SignedRequest, VerifierConfig, verify};

let identity = verify(&request, &config, &jwks, &replay_store).await?;
```

### Framework integration

Framework wiring lives in the adapter crates, not here:

- **Axum**: enable the `devsig` feature on `authkestra-axum` and use
  `authkestra_axum::devsig::DeviceSignatureLayer` (a `tower::Layer`) plus the
  `authkestra_axum::devsig::AuthDeviceSignature` extractor. See
  [`authkestra-axum`'s README](../authkestra-axum/README.md) and
  `crates/authkestra/examples/axum_devsig/`
  (`cargo run -p authkestra --example axum_devsig --all-features`).
- **Actix Web**: enable the `devsig` feature on `authkestra-actix` and use
  `authkestra_actix::devsig::DeviceSignatureAuth` (an `actix_web::dev::Transform` middleware)
  plus the `authkestra_actix::devsig::AuthDeviceSignature` extractor. See
  [`authkestra-actix`'s README](../authkestra-actix/README.md) and
  `crates/authkestra/examples/actix_devsig/`
  (`cargo run -p authkestra --example actix_devsig --all-features`).

Both adapters buffer the request body ahead of their framework's own extraction (needed for the
`bdh` check) and call this crate's plain [`verify`] function underneath — see their `devsig`
module docs for why neither implements an `authkestra-engine` `AuthenticationStrategy<I>` today.
