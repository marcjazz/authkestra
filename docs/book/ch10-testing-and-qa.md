# Chapter 10: Testing & QA Strategy

Ensuring the reliability and correctness of an authentication framework is paramount. This chapter details the testing strategy, tools, and Quality Assurance (QA) practices used within the Authkestra project.

## Core Philosophy

Our testing philosophy is built on three pillars:

1. **High Confidence over High Coverage**: While we aim for high test coverage, we prioritize meaningful tests that verify complex state transitions and edge cases over trivial getter/setter tests.
2. **Deterministic Tests**: Tests must not rely on external live network calls, ensuring they are fast, reliable, and run consistently in CI environments.
3. **Typestate Verification**: We heavily rely on Rust's type system to make invalid states unrepresentable, reducing the need for tests that check for "impossible" conditions.

## Unit Testing the Core Engine

The `authkestra-engine` crate is tested using standard Rust unit tests. We focus on:

- **Cryptographic Operations**: Verifying token generation, signature validation, and hashing algorithms function correctly.
- **State Machine Transitions**: Testing the logical steps of authentication flows (e.g., ensuring an authorization code can only be exchanged once).
- **Protocol conformance**: `crates/authkestra-engine/tests/` holds standalone suites for the
  OAuth2, device, and client-credentials (including `private_key_jwt`) flows.

Authorization *policy* evaluation is deliberately absent from this list: there is no policy engine
to test (see Chapter 5). What exists is the `Guard` + `AuthenticationStrategy` chain, tested in
`authkestra-resource`.

## Mocking External Providers with Wiremock

Authkestra integrates with numerous external OAuth/OIDC providers (GitHub, Google, etc.). To test these integrations without making live network requests, we utilize the `wiremock` crate.

`wiremock` allows us to spin up a local HTTP server during the test run and configure it to respond with specific payloads, simulating the behavior of the external provider.

- **Success Scenarios**: Mocking successful token exchanges and user profile retrieval.
- **Failure Scenarios**: Simulating provider outages (500 errors), invalid client secrets (401 errors), or malformed JSON responses to ensure Authkestra handles errors gracefully.

## Integration Testing

Integration tests ensure that the various components of Authkestra (Core, Adapters, Framework Integrations) work together correctly.

- **Database Adapters**: We use `testcontainers` to run tests against real database instances (Postgres, MySQL and Redis spun up via Docker) to verify schema migrations, queries, and data persistence. `docker-compose.yml` at the repository root provides the same services for local runs.
- **Framework Integration (Axum/Actix)**: Each adapter carries its own integration suite that drives the built `Engine` through the framework's own test harness — `tower::ServiceExt::oneshot` for Axum, `actix_web::test` for Actix — so route mounting, middleware, extractors and cookie handling are all exercised over real HTTP request/response types. They live at:
  - `crates/authkestra-axum/tests/engine_session_integration.rs` and `engine_token_integration.rs`
  - `crates/authkestra-actix/tests/engine_session_integration.rs`, `engine_token_integration.rs` and `auth_extensions_integration.rs`
  - `crates/authkestra-{axum,actix}/tests/devsig_test.rs` for device-bound signatures

  Between them they cover the full login → callback → session → logout round trip, `AuthSession` /
  `AuthToken` extraction, and the CSRF-state, missing-cookie and provider-failure rejection paths.
- **Examples as tests**: `crates/authkestra/tests/examples_e2e.rs` spawns each OAuth example binary
  against a `wiremock` stand-in for the upstream provider and asserts the login redirect, so an
  example that stops wiring together fails CI rather than rotting silently.

## Continuous Integration (CI)

Our CI pipeline (`.github/workflows/ci.yml`) enforces quality on every pull request. All jobs run
on stable Rust:

- **`cargo test --workspace --all-features`**: all unit and integration tests.
- **`cargo clippy --workspace --all-features -- -D warnings`**: idiomatic Rust practices, warnings
  treated as errors.
- **`cargo fmt --all -- --check`**: strict code formatting.
- **Coverage**: `cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info --fail-under-lines 84`
  — the build fails below the line-coverage threshold.
- **Dependency policy**: `cargo-deny` enforces the licence, advisory and source rules in
  `deny.toml`.

Run all five locally before opening a PR; each is the exact command CI runs, so reproducing a
failure never depends on guessing the flags.

By maintaining this rigorous testing strategy, we ensure Authkestra remains a robust and trustworthy foundation for application security.
