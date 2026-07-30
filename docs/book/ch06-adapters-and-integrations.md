# Chapter 6: Adapters and Integrations

To be truly framework-agnostic, the core engine must not know about HTTP requests or specific database connections. Adapters bridge this gap. Our architecture strictly separates interfaces from implementations—for example, treating `authkestra-session` purely as a contract by default, while implementations plug in dynamically via feature flags (e.g., `memory`, `redis`).

## Web Framework Adapters

We provide first-class integration layers for:

- **Axum** (`authkestra-axum`)
- **Actix Web** (`authkestra-actix`)

These are not just loose helpers, but robust, native-feeling extensions providing middleware, extractors, and routing guards. They map standard `AuthContext` requests into the framework's native HTTP response types.

### Supported Session Providers

- **Memory** (`memory` feature in `authkestra-session`) for local development.
- **Redis** (`redis` feature in `authkestra-session`) via `redis-rs`.
- **SQL** (`sql-postgres`, `sql-mysql` features in `authkestra-session`) for Postgres, MySQL.

## Database Adapters

For session storage and user data, adapters rely strictly on traits (`SessionStore`, etc), ensuring developers can plug their existing databases directly into Authkestra via feature-flagged implementations or custom code.

## Device-Bound Signature Authentication (`authkestra-devsig`)

`authkestra-devsig` is a fourth request-authentication family, alongside OAuth/OIDC, sessions,
and Basic: per-request proof of possession of a device-bound private key, with the public key
and its identity binding travelling in the request itself (an `X-Signature` JWS signed by the
device, plus an `X-Attestation` JWS signed by the Issuer binding that key to an identity).
Verification needs no session store, no token introspection, and no per-request network call —
any service holding a cached Issuer JWKS can verify a request independently. See
[authkestra#137](https://github.com/marcjazz/authkestra/issues/137) for the original proposal.

Per the "Framework Agnostic" rule above, `authkestra-devsig` itself ships only the plain
`verify()` function and the types it needs — it does not depend on axum, actix, or any other web
framework. Framework wiring lives in the adapter crates, following the same "extractors vs
middleware" split as the rest of this chapter:

- **Axum** (`authkestra-axum`, `devsig` feature): `DeviceSignatureLayer` is a `tower::Layer` that
  buffers the request body ahead of axum's own extraction (needed for the `bdh` body-hash
  check), calls `authkestra_devsig::verify`, and injects the verified identity into request
  extensions on success — or short-circuits with `401`/`413` on failure. The
  `AuthDeviceSignature` extractor reads that identity back out via `FromRequestParts`. See
  `crates/authkestra-axum/examples/devsig/` for a runnable example.
- **Actix Web** (`authkestra-actix`, `devsig` feature): `DeviceSignatureAuth` is the equivalent
  `actix_web::dev::Transform` middleware, with an `AuthDeviceSignature` extractor implementing
  `FromRequest`. See `crates/authkestra-actix/examples/devsig/` for a runnable example.

Both adapters buffer the whole body before verification (never just streaming it through) —
buffering is a deliberate, explicitly-capped memory trade-off, because the `bdh` check needs the
complete body to hash it. Both wrap `authkestra_devsig::DeviceIdentity` in a small newtype
(`AuthDeviceSignature`) rather than implementing the framework's extractor trait directly on it:
`DeviceIdentity` is defined in `authkestra-devsig` and the extractor trait (`FromRequestParts` /
`FromRequest`) is defined in axum/actix, so neither is local to the adapter crate — Rust's
orphan rules require the impl to live on a type the adapter crate owns instead.

Neither adapter implements `authkestra-engine`'s `AuthenticationStrategy<I>` today: that trait's
`authenticate(&self, parts: &Parts)` only ever sees header/URI data, never the body, so it
cannot express the `bdh` check without silently skipping it — not a reasonable default for a
scheme designed to protect write requests. Migrating either adapter to a body-aware
`authkestra-engine` trait, if one is added, is a matter of swapping which caller builds a
`SignedRequest` and calls `verify()`; the verification algorithm itself does not change.

### Architectural Decisions & Future Direction

- **Extractors vs Middleware:** In Axum and Actix, both serve different purposes and we must provide both. Custom extractors (`async fn handler(user: Identity)`) provide the best developer experience (DX) for route-specific logic. Middleware is better suited for global URL protection rules.
- **Database Schema:** Enforcing a specific database schema is a fatal mistake that alienates 90% of developers who have existing databases. We must provide traits (e.g., `UserStore`), allowing developers to map their existing tables to our interfaces instead of forcing migrations.
