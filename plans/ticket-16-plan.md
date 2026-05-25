# Plan: Ticket 16 - Improve Examples Developer Experience (DX)

## Objective
Improve the developer experience (DX) of our examples by standardizing the Rust structure, breaking them into smaller, atomic, single-feature pieces, and cleaning up the code (such as avoiding returning raw HTML strings). 

## 1. Directory Restructuring (Standard Rust Examples)
- **Current Issue**: Examples are currently stored as binaries in `authkestra-examples/src/bin/`.
- **Solution**: Move all example files from `src/bin/` to a standard `examples/` directory inside the `authkestra-examples` crate.
  - This allows running them via `cargo run --example <name>`.
  - The `authkestra-examples` crate will act as a container for these examples, sharing the common dependencies defined in its `Cargo.toml`.
- **Action**: Rename `authkestra-examples/src/bin` to `authkestra-examples/examples`. Remove the `src/` directory from `authkestra-examples` completely since it does not provide a library or primary binary.

## 2. Refactoring into Atomic Pieces
- **Current Issue**: Examples might mix multiple concerns or feel bloated.
- **Solution**: Break down examples to focus on one specific concept at a time.
  - Basic setups (just engine + adapter)
  - Specific flows (Client Credentials, Device Flow, OAuth2/OIDC)
  - Session management (Memory vs Redis vs SQL)
  - Resource servers & JWTs
- **Proposed Atomic Examples**:
  - `axum_basic_setup.rs`: Just setting up the engine with a mock auth method in Axum.
  - `actix_basic_setup.rs`: Just setting up the engine with a mock auth method in Actix.
  - `axum_oauth2_github.rs`: GitHub OAuth2 login flow with Axum.
  - `axum_oidc_google.rs`: Google OIDC login flow with Axum.
  - `axum_session_redis.rs`: Axum example focusing on Redis session store.
  - `axum_client_credentials.rs`: Machine-to-machine client credentials flow.
  - `axum_device_flow.rs`: Device authorization grant flow.
  - `axum_resource_server.rs`: Validating JWTs.
  - *(Similar atomic equivalents for Actix as needed, though Axum can be the primary focus for full coverage)*

## 3. Code Cleanup (No Raw HTML in Rust)
- **Current Issue**: Returning raw HTML strings in Rust examples makes the code messy and hard to read.
- **Solution**: 
  - Instead of writing inline HTML, we will provide a `static/` folder inside `authkestra-examples` containing a basic `index.html` (and simple JS/CSS).
  - Examples will serve these static files using `tower-http` (for Axum) or `actix-files` (for Actix).
  - The Rust code will act purely as an API (returning JSON or handling redirects), while the static HTML/JS handles the UI, mimicking a real-world SPA or decoupled frontend architecture.

## Execution Steps
1. Create the `authkestra-examples/examples` directory and `authkestra-examples/static` directory.
2. Add `tower-http` (with `fs` feature) and `actix-files` to `authkestra-examples/Cargo.toml`.
3. Migrate and split the existing `src/bin/*.rs` files into the new `examples/*.rs` structure.
4. Replace raw HTML strings in the Rust code with static file serving and clean JSON responses.
5. Update documentation and `README.md` to reflect the new `cargo run --example` commands.
6. Verify all examples compile and run correctly.
