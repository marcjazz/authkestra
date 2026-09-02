---
title: Continuous Access Evaluation (CAEP/SSF)
description: Ingesting and validating Security Event Tokens so an external IdP or EDR can tell your service that something changed.
---

A session that was legitimate when it started does not stay legitimate. The user's password gets
reset, their laptop drops out of compliance, an administrator revokes their session — and none of
that reaches your service until the next token refresh, which may be an hour away.

The **Shared Signals Framework** closes that gap: a cooperating provider pushes you a signed
**Security Event Token (SET)** the moment something changes. `authkestra-ssf` is the receiving
side of that exchange.

## Standards implemented

| Specification | What it defines | Where it lands |
| --- | --- | --- |
| [RFC 8417](https://www.rfc-editor.org/rfc/rfc8417) | The SET itself: a JWT whose payload is a set of events | `SecurityEventToken`, `SetVerifier` |
| [RFC 8935](https://www.rfc-editor.org/rfc/rfc8935) | Push delivery over HTTP, and the 202/400 response semantics | `PushReceiver`, `PushResponse` |
| [RFC 9493](https://www.rfc-editor.org/rfc/rfc9493) | Structured subject identifiers (`sub_id`) | `SubjectIdentifier` |
| [OpenID CAEP 1.0](https://openid.net/specs/openid-caep-specification-1_0.html) | The event vocabulary: session revoked, credential change, and friends | `CaepEvent` |

## What is implemented today — and what is not

Implemented:

- **Ingest and validate SETs.** Explicit `typ` checking, an algorithm allow-list that can never
  contain `none`, signature verification against a single key or a `kid`-based resolver, issuer
  and audience checks, `iat` freshness with configurable leeway and optional maximum age, `exp`
  honoured when a transmitter sends one, non-empty `events`, and `jti` replay detection.
- **Typed CAEP events.** All five CAEP 1.0 event types with their specific claims. Event types
  this crate does not model (RISC, SCIM, vendor extensions) are preserved verbatim rather than
  dropped, so a handler that understands them still can.
- **A framework-agnostic push receiver** implementing the RFC 8935 response semantics, including
  the registered error codes (`invalid_request`, `invalid_key`, `invalid_issuer`,
  `invalid_audience`, `authentication_failed`, `access_denied`).

Not implemented yet:

- **Session state is not updated when a revocation signal arrives.** Nothing in the engine reacts
  to a `session-revoked` event on its own; you write a `SetHandler` and do it yourself.
- **No middleware rejects tokens invalidated by a CAEP event.**
- **No Axum or Actix routes are wired.** `PushReceiver::receive` returns a plain data structure;
  turning it into a route is a few lines in your own handler today.

The three gaps are tracked in
[authkestra#25](https://github.com/marcjazz/authkestra/issues/25).

## Setting up a receiver

```toml
[dependencies]
authkestra-ssf = "0.7"
jsonwebtoken = { version = "11", features = ["rust_crypto"] }
```

```rust
use std::sync::Arc;
use std::time::Duration;

use authkestra_ssf::{InMemorySetReplayGuard, PushReceiver, SetVerifier};
use jsonwebtoken::{Algorithm, DecodingKey};

let verifier = SetVerifier::builder("https://idp.example.com/")
    .audience("https://sp.example.com/caep")
    .algorithms([Algorithm::EdDSA])
    .key(transmitter_key)
    .max_age(Duration::from_secs(60 * 60))
    .replay_guard(Arc::new(InMemorySetReplayGuard::new(Duration::from_secs(60 * 60))))
    .build()?;

let receiver = PushReceiver::new(Arc::new(verifier))
    .with_handler(Arc::new(MyHandler));
```

Then, in whatever HTTP handler you expose at your delivery endpoint:

```rust
let response = receiver.receive(content_type_header, body_bytes).await;
// response.status()           -> 202, 400 or 500
// response.content_type()     -> "application/json" on failure
// response.content_language() -> "en" on failure (RFC 8935 §2.3 requires it)
// response.body()             -> {"err": ..., "description": ...} on failure
```

## Reacting to an event

```rust
use async_trait::async_trait;
use authkestra_ssf::{CaepEvent, HandlerError, SecurityEventToken, SetHandler};

struct MyHandler;

#[async_trait]
impl SetHandler for MyHandler {
    async fn handle(
        &self,
        set: &SecurityEventToken,
        event: &CaepEvent,
    ) -> Result<(), HandlerError> {
        if let CaepEvent::SessionRevoked(revoked) = event {
            // `revoked.metadata.subject` is the RFC 9493 subject identifier, when the
            // transmitter sent one; `set.sub_id` is the SET-level one.
            let _ = revoked;
            // ... look the subject up and drop its sessions ...
        }
        Ok(())
    }
}
```

Returning `HandlerError::Rejected` answers the transmitter with `400 access_denied`; returning
`HandlerError::Internal` answers `500`, so a conformant transmitter retries. Handlers run *before*
the response is produced, because this crate has no store of its own — if you want the
asynchronous shape RFC 8935 §2 suggests, enqueue inside the handler and return immediately.

## Behaviours that surprise people

- **A retransmitted SET is answered `202`, not an error.** RFC 8935 §2 requires the recipient to
  respond to a repeat transmission exactly as it would to a first one, so replay detection
  suppresses handler dispatch, not the acknowledgement.
- **`Content-Type` must be `application/secevent+jwt`.** Anything else is a `400 invalid_request`.
- **Explicit typing is mandatory here.** RFC 8417 §2.3 only requires `typ: secevent+jwt` when a
  SET could be confused with another kind of JWT — which is exactly the situation a general
  receiver is in, so this crate always requires it.
- **`exp` is optional; `nbf` is ignored.** A SET describes something that already happened, so
  RFC 8417 §2.2 discourages `exp` entirely and never profiles `nbf`. Freshness comes from `iat`.
- **An empty `jti` is refused.** RFC 8417 §2.2 makes `jti` the SET's unique identifier. An empty
  or whitespace-only one identifies nothing, and would collapse the replay guard to one slot per
  issuer — so it is a `400 invalid_request`.

## Body size limits

`PushReceiver` refuses any body larger than `DEFAULT_MAX_BODY_BYTES` (1 MiB) with
`400 invalid_request`, before it parses anything. Change it with:

```rust
let receiver = PushReceiver::new(verifier).with_max_body_bytes(64 * 1024);
```

**Set a limit in your HTTP layer as well.** By the time `receive` is called, the body has already
been read into memory by the framework, so this check is a second line of defence — it stops an
oversized body reaching the parser and the signature verifier, but it cannot prevent the
allocation. What actually bounds what gets buffered is axum's `DefaultBodyLimit`, actix's
`PayloadConfig`, or your reverse proxy's `client_max_body_size`.

## Building the models in your own tests

The public models are `#[non_exhaustive]`, so they cannot be built with struct-literal syntax from
outside the crate — but every one of them has a constructor, precisely so that the code you write
to map a CAEP event onto your own domain stays unit-testable without minting and verifying a real
SET:

```rust
use authkestra_ssf::{CaepMetadata, CredentialChange, CredentialType, ChangeType, SecurityEventToken};

let set = SecurityEventToken::new("https://idp.example.com/", "jti-1", 1_700_000_000, events);
let mut change = CredentialChange::new(CredentialType::Password, ChangeType::Update);
change.metadata = CaepMetadata::empty();
```

None of these constructors validate anything: a SET your service should act on comes out of
`SetVerifier`, never out of a constructor.
