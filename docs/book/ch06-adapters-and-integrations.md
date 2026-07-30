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

## Device/Service Attestation Issuance (OP)

Beyond the standard OIDC provider surface, `authkestra-op` (behind the `op`
feature) can issue **device/service attestations**: short-lived,
`cnf.jkt`-bound JWS tokens that let a mobile device or backend service prove
possession of a key it enrolled, without a bearer token ever leaving the
device. This is the Issuer side of the device-bound-signature authentication
method. Three handlers, framework-agnostic in `authkestra-op`, are wired
into both adapters:

| Route | Purpose |
|---|---|
| `POST /enrol` | Validate the caller's public key and second factor, issue a single-use proof-of-possession challenge. |
| `POST /enrol/complete` | Consume the challenge, verify the signature was produced by the enrolled key, compute `cnf.jkt` from that key (never from caller input), and mint the attestation. |
| `POST /reissue` | Silently renew a near-expiry attestation by re-proving possession of the same key — no second factor required, since continuity of the key stands in for it. |

Both `authkestra-axum` and `authkestra-actix` wire these three routes with
the same `tracing` instrumentation the rest of each adapter's handlers use.

**Axum** exposes them through a router split from the main OIDC router
rather than folded into it, so an application that only wants standard OIDC
never has to supply attestation-specific dependencies just to keep
compiling:

```rust,ignore
let app = Router::new()
    .merge(state.op_axum_router())              // /authorize, /token, /userinfo, ...
    .merge(state.op_axum_attestation_router())   // /enrol, /enrol/complete, /reissue
    .with_state(state);
```

**Actix** wires the same three routes via `OpExt::op_actix_scope()`,
resolving each dependency (`EnrolmentChallengeStore`, `SecondFactorVerifier`,
`TokenManager`, `AttestationConfig`) from `app_data` — an application that
has not registered the optional `AttestationStatusProvider` simply gets
`None` at the extractor, exactly like Axum's `Option<Arc<dyn
AttestationStatusProvider>>: FromRef<AppState>`.

The ceremony has two pluggable hooks a host application implements, since
`authkestra-op` deliberately does not hardcode a telecom integration or an
attribute/revocation store:

- **`SecondFactorVerifier`** — verifies whatever proof the caller submits at
  enrolment (SMS/TOTP for a device; an out-of-band admin approval or
  one-time bootstrap secret for a service principal).
- **`AttestationStatusProvider`** *(optional)* — supplies current
  attributes at re-issuance time, and can refuse re-issuance outright for a
  revoked principal. If not configured, re-issuance falls back to copying
  the previous attestation's attributes forward, still bound by
  proof-of-possession.

The enrolment-challenge store itself is just another `EnrolmentChallengeStore`
trait — implemented as a blanket impl over any `KvStore` + `AtomicConsume`
backend, so Redis/SQL/in-memory all work via the same mechanism session and
OP data already use elsewhere in this chapter.

See `crates/authkestra/examples/axum/op_server_attestation.rs` and
`crates/authkestra/examples/actix/op_server_attestation.rs` for a
self-contained, runnable walkthrough of enrolment and re-issuance end to end
(no external services required — the challenge store is an in-memory
`MemoryStore` for the example).

### Architectural Decisions & Future Direction

- **Extractors vs Middleware:** In Axum and Actix, both serve different purposes and we must provide both. Custom extractors (`async fn handler(user: Identity)`) provide the best developer experience (DX) for route-specific logic. Middleware is better suited for global URL protection rules.
- **Database Schema:** Enforcing a specific database schema is a fatal mistake that alienates 90% of developers who have existing databases. We must provide traits (e.g., `UserStore`), allowing developers to map their existing tables to our interfaces instead of forcing migrations.
